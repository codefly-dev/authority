package forward

// The gRPC face: a gRPC server that answers every method of the module it
// stands in front of by deciding, stamping and forwarding the call as opaque
// frames. It knows no method of the module; the authority decides each.

import (
	"context"
	"errors"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Decide is the hop's decision for one call to method: the module it is for and
// who it acts for.
type Decide func(ctx context.Context, method string, md metadata.MD) (decide.Decision, error)

// Proxy forwards a decided call to the module's own connection.
type Proxy struct {
	Decide    Decide
	Upstreams map[string]*grpc.ClientConn
	Signer    *callstamp.Signer
	// Ready must be this signer's RegistrationLease.Ready; nil refuses. It is
	// publication state, not proof that downstream verifiers know the key.
	Ready func() bool
	// Refused is told every refusal, so the hop's log names it.
	Refused func(method string, err error)
	// Sink, when set, receives every refusal this face makes, beside the
	// log: those Refused is told, and those the log never named (no
	// admission-key publication, an admission that cannot be signed, a
	// decision with no connection behind it). nil records nothing.
	Sink Sink
}

// ServerOptions make the hop's server answer every method it does not serve
// itself through the proxy. The codec carries the module's messages as opaque
// frames and the hop's own (health) as protobuf.
func (p *Proxy) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{grpc.UnknownServiceHandler(p.handle), grpc.ForceServerCodec(Codec{})}
}

// CallOptions carry opaque frames to the module without choosing a transport.
// The caller's host.DialOptions remains the sole transport authority.
func CallOptions() []grpc.CallOption {
	return []grpc.CallOption{grpc.ForceCodec(Codec{})}
}

func (p *Proxy) handle(_ any, in grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(in)
	md, _ := metadata.FromIncomingContext(in.Context())
	if err := requirePublication(p.Ready); err != nil {
		refused(in.Context(), p.Refused, p.Sink, false, method, md, decide.Decision{}, err)
		return err
	}
	decision, err := p.Decide(in.Context(), method, md)
	if err != nil {
		refused(in.Context(), p.Refused, p.Sink, true, method, md, decision, err)
		return err
	}
	module, id := decision.Module, decision.Identity
	out := metadata.MD{}
	for key, values := range md {
		if !strings.HasPrefix(key, ":") && key != "content-type" && key != "user-agent" && !strings.HasPrefix(key, "grpc-") {
			out[key] = values
		}
	}
	// The module receives what the hop vouches for, and no credential of the
	// caller's.
	hop.StripCredentials(out)
	// This final check is the admission point, not a reservation through
	// stamping or I/O. An admitted call may finish across Close or expiry.
	if err := requirePublication(p.Ready); err != nil {
		refused(in.Context(), p.Refused, p.Sink, false, method, md, decision, err)
		return err
	}
	if err := hop.Stamp(out, id, p.Signer, method, module, time.Now()); err != nil {
		unsigned := status.Error(codes.Unauthenticated, err.Error())
		refused(in.Context(), p.Refused, p.Sink, false, method, md, decision, unsigned)
		return unsigned
	}
	// The call lives no longer than the Work Context that admitted it: a
	// stream still open at its expiry is ended here, and opened again only on
	// a context the authority checks again.
	ctx, cancel := hop.UntilExpiry(metadata.NewOutgoingContext(in.Context(), out), time.Unix(id.Expires, 0))
	defer cancel()
	// told is the call as the sink is told of it, should it be refused from here.
	told := func(logged bool, err error) error {
		refused(in.Context(), p.Refused, p.Sink, logged, method, md, decision, err)
		return err
	}
	if decision.Route == nil {
		return told(false, status.Error(codes.Internal, "the hop decision names no published route"))
	}
	upstream, ok := p.Upstreams[decision.Route.Address]
	if !ok {
		return told(false, status.Errorf(codes.Internal, "the hop has no connection to %s", module))
	}
	expired := func() error { return told(true, hop.ExpiredStatus()) }
	up, err := upstream.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, method)
	if err != nil {
		if hop.Expired(ctx) {
			return expired()
		}
		return p.unanswered(in.Context(), method, md, decision, err)
	}
	sent, received := make(chan error, 1), make(chan error, 1)
	go func() { sent <- forward(in, up) }()
	go func() { received <- back(up, in) }()
	ended := ctx.Done()
	for {
		select {
		case err := <-sent:
			if hop.Expired(ctx) {
				return expired()
			}
			if err != nil {
				return status.Errorf(codes.Internal, "the hop could not forward the call to the module: %v", err)
			}
			sent = nil // the caller is done sending; the reply is still coming
		case err := <-received:
			// The module's stream ends with the hop's context, so its last
			// status may be that ending's; the caller is told the expiry.
			if err != nil && hop.Expired(ctx) {
				return expired()
			}
			in.SetTrailer(up.Trailer())
			return err
		case <-ended:
			if hop.Expired(ctx) {
				return expired()
			}
			ended = nil // the caller ended the call; the module's stream says how
		}
	}
}

// unanswered refuses a call whose stream to the module could not be opened. A
// caller whose request ended is answered with the code its context ended
// with. Otherwise the module did not answer, Unavailable; the transport error,
// which can name the module's internal address, goes to the hop's log, never
// to the caller.
//
// Once the stream is open, every failure passes through as gRPC reports it:
// gRPC does not tell a transport failure from the module's own status there,
// and rewording one would reword the other.
func (p *Proxy) unanswered(ctx context.Context, method string, md metadata.MD, decision decide.Decision, err error) error {
	if ended := ctx.Err(); ended != nil {
		return status.Errorf(status.FromContextError(ended).Code(), "the caller's request ended before the module answered: %v", ended)
	}
	failed := status.Errorf(codes.Unavailable, "the module did not answer: %v", err)
	if p.Refused == nil {
		slog.Warn("hop: the module did not answer", "method", method, "error", err)
	}
	refused(ctx, p.Refused, p.Sink, true, method, md, decision, failed)
	return status.Error(codes.Unavailable, "the module did not answer")
}

func requirePublication(ready func() bool) error {
	if ready == nil || !ready() {
		return status.Error(codes.Unavailable, "the hop has no current admission-key publication lease")
	}
	return nil
}

// back relays the module's header, messages and status to the caller.
func back(up grpc.ClientStream, in grpc.ServerStream) error {
	for first := true; ; first = false {
		f := &Frame{}
		if err := up.RecvMsg(f); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if first {
			if header, err := up.Header(); err == nil {
				if err := in.SendHeader(header); err != nil {
					return err
				}
			}
		}
		if err := in.SendMsg(f); err != nil {
			return err
		}
	}
}

// forward relays the caller's messages to the module, then closes its side.
func forward(in grpc.ServerStream, up grpc.ClientStream) error {
	for {
		f := &Frame{}
		if err := in.RecvMsg(f); err != nil {
			if errors.Is(err, io.EOF) {
				return up.CloseSend()
			}
			return err
		}
		if err := up.SendMsg(f); err != nil {
			return err
		}
	}
}

// Frame is one message, carried without being decoded.
type Frame struct{ Payload []byte }

// Codec passes a Frame through untouched and encodes anything else as protobuf.
type Codec struct{}

// Name is protobuf's, so neither end sees a different content type.
func (Codec) Name() string { return "proto" }

// Marshal returns a frame's bytes, or the message's protobuf encoding.
func (Codec) Marshal(v any) ([]byte, error) {
	if f, ok := v.(*Frame); ok {
		return f.Payload, nil
	}
	m, ok := v.(proto.Message)
	if !ok {
		return nil, status.Errorf(codes.Internal, "the hop cannot encode %T", v)
	}
	return proto.Marshal(m)
}

// Unmarshal keeps a frame's bytes, or decodes the message.
func (Codec) Unmarshal(data []byte, v any) error {
	if f, ok := v.(*Frame); ok {
		f.Payload = append([]byte(nil), data...)
		return nil
	}
	m, ok := v.(proto.Message)
	if !ok {
		return status.Errorf(codes.Internal, "the hop cannot decode into %T", v)
	}
	return proto.Unmarshal(data, m)
}
