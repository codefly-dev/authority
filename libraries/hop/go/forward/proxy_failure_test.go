package forward_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

const readProcedure = "/example.v1.Service/Read"

// withContext is a call carrying a Work Context, which the hop's stamp signs over.
func withContext() context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, "wc-model")
}

// throughHop is a gRPC face in front of upstream, deciding every call for the
// module, and the log of what it refused.
func throughHop(t *testing.T, upstream *grpc.ClientConn) (grpc.ClientConnInterface, *[]string) {
	t.Helper()
	refused := &[]string{}
	p := &forward.Proxy{
		Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
			return decide.Decision{Module: "model", Route: &routing.RouteEndpoint{Address: "model", Transport: "grpc"},
				Identity: hop.Identity{Expires: time.Now().Add(time.Minute).Unix(), Owner: "jane", OwnerKind: "human", Tenant: "acme"}}, nil
		},
		Upstreams: map[string]*grpc.ClientConn{"model": upstream},
		Signer:    hoptest.Signer(proof), Ready: published(t, hoptest.Signer(proof)),
		Refused: func(method string, err error) { *refused = append(*refused, method+": "+err.Error()) },
	}
	return serve(t, p.ServerOptions(), func(*grpc.Server) {}), refused
}

// A module that cannot be dialled did not answer: the caller is told so,
// Unavailable, and not the transport error, which names the module's internal
// address. The hop's log is told that.
func TestAModuleThatCannotBeDialledIsUnavailableAndItsAddressStaysInTheLog(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := closed.Addr().String()
	_ = closed.Close()
	upstream, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(forward.CallOptions()...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	through, refused := throughHop(t, upstream)

	err = through.Invoke(withContext(), readProcedure, &emptypb.Empty{}, &emptypb.Empty{})
	if status.Code(err) != codes.Unavailable || status.Convert(err).Message() != "the module did not answer" {
		t.Fatalf("the caller was told %v", err)
	}
	if len(*refused) != 1 || !strings.Contains((*refused)[0], address) {
		t.Fatalf("the hop's log was told %v", *refused)
	}
}

// A module's own status reaches the caller as it is: code and message,
// Unavailable included. Only a module that never answered is reworded.
func TestAModulesOwnStatusReachesTheCallerAsIs(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.FailedPrecondition, codes.PermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			listener := bufconn.Listen(1 << 20)
			module := grpc.NewServer(grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
				return status.Error(code, "the module's own reason")
			}))
			go func() { _ = module.Serve(listener) }()
			t.Cleanup(module.Stop)
			through, refused := throughHop(t, dial(t, listener, grpc.WithDefaultCallOptions(forward.CallOptions()...)))

			err := through.Invoke(withContext(), readProcedure, &emptypb.Empty{}, &emptypb.Empty{})
			if status.Code(err) != code || status.Convert(err).Message() != "the module's own reason" {
				t.Fatalf("the caller was told %v, want %v the module's own reason", err, code)
			}
			if len(*refused) != 0 {
				t.Fatalf("a module's answer is not a refusal of the hop's: %v", *refused)
			}
		})
	}
}
