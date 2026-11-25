package forward_test

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// narrowing is a module whose handlers narrow to the owners that admitted the
// call. It names no permission: it reads what the hop handed it.
type narrowing struct{ reached int }

func (n *narrowing) read(ctx context.Context) string {
	n.reached++
	admitted, ok := hop.Admitted(ctx)
	if !ok {
		return "no admission"
	}
	required := admitted.Required()
	out := "owners=" + strings.Join(required.Owners(), ",")
	if required.Whole() {
		out += " whole"
	}
	return out
}

func (n *narrowing) Version(ctx context.Context) (string, error) { return n.read(ctx), nil }

// Decision 2, through the hop itself: an admitted call reaches the module with
// the selection of what admitted it, on a unary call and on a stream; what a
// caller wrote in its place is stripped; a refused call reaches nothing.
func TestTheHopHandsTheModuleWhatAdmittedTheCall(t *testing.T) {
	a := &authority{Authority: hoptest.New(t), revoked: map[string]bool{}}
	identity := policy.Method{Requires: []policy.Permission{policy.Of("console.identity", "read")}}
	verifier, err := hop.NewVerifier(context.Background(), a.PublishHop(proof), "console", hoptest.Replay(),
		hop.Declarations(map[string]policy.Method{versionProcedure: identity, watchProcedure: identity}))
	if err != nil {
		t.Fatal(err)
	}
	m := &narrowing{}
	moduleListener := bufconn.Listen(1 << 20)
	moduleServer := grpc.NewServer(grpc.UnaryInterceptor(verifier.UnaryServerInterceptor()), grpc.StreamInterceptor(verifier.StreamServerInterceptor()))
	moduleServer.RegisterService(&grpc.ServiceDesc{
		ServiceName: moduleService,
		HandlerType: (*versioner)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Version", Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			in := new(emptypb.Empty)
			if err := decode(in); err != nil {
				return nil, err
			}
			return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: versionProcedure}, func(ctx context.Context, _ any) (any, error) {
				return wrapperspb.String(m.read(ctx)), nil
			})
		}}},
		Streams: []grpc.StreamDesc{{StreamName: "Watch", ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
			if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
				return err
			}
			return stream.SendMsg(wrapperspb.String(m.read(stream.Context())))
		}}},
	}, m)
	go func() { _ = moduleServer.Serve(moduleListener) }()
	t.Cleanup(moduleServer.Stop)
	p := &forward.Proxy{
		Decide: decide.Decider{Routes: &routing.Routing{Endpoints: []routing.RouteEndpoint{{Audience: "console", Transport: "grpc", Address: "console",
			Methods: []string{versionProcedure, watchProcedure}}}}, Authority: a, Modules: map[string]bool{"console": true}}.Decide,
		Upstreams: map[string]*grpc.ClientConn{"console": dial(t, moduleListener, grpc.WithDefaultCallOptions(forward.CallOptions()...))},
		Signer:    hoptest.Signer(proof), Ready: published(t, hoptest.Signer(proof)),
	}
	through := serve(t, p.ServerOptions(), func(*grpc.Server) {})

	forged, err := hop.EncodeGrants([]hop.Grant{{Kind: "console.identity", Action: "read"}}) // the whole kind
	if err != nil {
		t.Fatal(err)
	}
	owned := func(owner string) *basev1.WorkScopeV1 {
		return &basev1.WorkScopeV1{ResourceKind: "console.identity", Actions: []string{"read"}, ResourceOwnerId: owner}
	}
	calling := func(scopes ...*basev1.WorkScopeV1) context.Context {
		return metadata.AppendToOutgoingContext(context.Background(), hop.WorkContextKey, a.Issue(t, "console", scopes...), hop.AdmittedKey, forged)
	}

	got, err := version(calling(owned("installation-a")), through)
	if err != nil || got != "owners=installation-a" {
		t.Fatalf("a call admitted for one installation read %q: %v", got, err)
	}
	got, err = version(calling(identityRead), through)
	if err != nil || got != "owners= whole" {
		t.Fatalf("a call admitted on the whole kind read %q: %v", got, err)
	}

	stream, err := through.NewStream(calling(owned("installation-b"), owned("installation-c")), &grpc.StreamDesc{ServerStreams: true}, watchProcedure)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	_ = stream.CloseSend()
	streamed := new(wrapperspb.StringValue)
	if err := stream.RecvMsg(streamed); err != nil || streamed.GetValue() != "owners=installation-b,installation-c" {
		t.Fatalf("a stream admitted for two installations read %q: %v", streamed.GetValue(), err)
	}

	// Nothing is stamped on a refused call: nothing is forwarded at all.
	reached := m.reached
	a.refuse = map[string]string{versionProcedure: "console requires console.identity:read, which the call does not hold"}
	if _, err := version(calling(owned("installation-a")), through); status.Code(err) != codes.PermissionDenied || m.reached != reached {
		t.Fatalf("a refused call: %v, the module reached %d more times", err, m.reached-reached)
	}
}
