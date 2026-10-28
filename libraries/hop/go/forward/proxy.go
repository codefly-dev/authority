package forward

// The gRPC face: a gRPC server that answers every method of the module it
// stands in front of by deciding, stamping and forwarding the call as opaque
// frames. It knows no method of the module; the authority decides each.

import (
	"context"
	"errors"
	callstamp "github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"io"
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
	if err := requirePublication(p.Ready); err != nil {
		return err
	}
	md, _ := metadata.FromIncomingContext(in.Context())
	decision, err := p.Decide(in.Context(), method, md)
	if err != nil {
		if p.Refused != nil {
			p.Refused(method, err)
		}
		return err
	}
	module, id := decision.Module, decision.Identity
	out := metadata.MD{}
	for key, values := range md {
		if !strings.HasPrefix(key, ":") && key != "content-type" && key != "user-agent" && !strings.HasPrefix(key, "grpc-") {
			out[key] = values
		}
	}
	// This final check is the admission point, not a reservation through
	// stamping or I/O. An admitted call may finish across Close or expiry.
	if err := requirePublication(p.Ready); err != nil {
		return err
	}
	if err := hop.Stamp(out, id, p.Signer, method, module, time.Now()); err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(in.Context(), out))
	defer cancel()
	if decision.Route == nil {
		return status.Error(codes.Internal, "the hop decision names no published route")
	}
	upstream, ok := p.Upstreams[decision.Route.Address]
	if !ok {
		return status.Errorf(codes.Internal, "the hop has no connection to %s", module)
	}
	up, err := upstream.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, method)
	if err != nil {
		return err
	}
	sent, received := make(chan error, 1), make(chan error, 1)
	go func() { sent <- forward(in, up) }()
	go func() { received <- back(up, in) }()
	for {
		select {
		case err := <-sent:
			if err != nil {
				return status.Errorf(codes.Internal, "the hop could not forward the call to the module: %v", err)
			}
			sent = nil // the caller is done sending; the reply is still coming
		case err := <-received:
			in.SetTrailer(up.Trailer())
			return err
		}
	}
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
