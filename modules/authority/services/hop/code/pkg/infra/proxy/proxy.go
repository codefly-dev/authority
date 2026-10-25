// Package proxy is the hop's local face: a gRPC server that answers every method
// of the module it stands in front of by deciding, stamping and forwarding the
// call as opaque frames. It knows no method of the module; the decision is the
// same for each until the module's declared policy reaches the hop.
package proxy

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"hop/pkg/business/decide"
)

// Decide is the hop's decision for one call to method: the module it is for and
// who it acts for.
type Decide func(ctx context.Context, method string, md metadata.MD) (decide.Decision, error)

// Proxy forwards a decided call to the module's own connection.
type Proxy struct {
	Decide    Decide
	Upstreams map[string]*grpc.ClientConn
	Proof     string
	// Refused is told every refusal, so the hop's log names it.
	Refused func(method string, err error)
}

// ServerOptions make the hop's server answer every method it does not serve
// itself through the proxy. The codec carries the module's messages as opaque
// frames and the hop's own (health) as protobuf.
func (p *Proxy) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{grpc.UnknownServiceHandler(p.handle), grpc.ForceServerCodec(Codec{})}
}

// DialOptions make a client connection carry opaque frames to the module.
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithDefaultCallOptions(grpc.ForceCodec(Codec{}))}
}

func (p *Proxy) handle(_ any, in grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(in)
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
	hop.Stamp(out, id, p.Proof)
	ctx, cancel := context.WithCancel(metadata.NewOutgoingContext(in.Context(), out))
	defer cancel()
	key := module
	if decision.Route != nil {
		key = decision.Route.Address
	}
	upstream, ok := p.Upstreams[key]
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
