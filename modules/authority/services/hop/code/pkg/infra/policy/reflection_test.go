package policy_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	hopv1 "github.com/codefly-dev/authority/libraries/hop/go/gen/authority/hop/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	reflectionv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"hop/pkg/business/decide"
	"hop/pkg/infra/policy"
)

// module serves reflection for one service whose methods carry declarations,
// built the way protoc writes them into a descriptor.
func module(t *testing.T, marks map[string]*hopv1.Policy) *grpc.ClientConn {
	t.Helper()
	empty := &descriptorpb.DescriptorProto{Name: proto.String("Empty")}
	service := &descriptorpb.ServiceDescriptorProto{Name: proto.String("ApiService")}
	for _, name := range []string{"WhoAmI", "Version", "Unmarked"} {
		m := &descriptorpb.MethodDescriptorProto{Name: proto.String(name), InputType: proto.String(".api.Empty"), OutputType: proto.String(".api.Empty")}
		if mark, ok := marks[name]; ok {
			m.Options = &descriptorpb.MethodOptions{}
			proto.SetExtension(m.Options, hopv1.E_Policy, mark)
		}
		service.Method = append(service.Method, m)
	}
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("api.proto"), Package: proto.String("api"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{empty}, Service: []*descriptorpb.ServiceDescriptorProto{service},
	}, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	files := &protoregistry.Files{}
	if err := files.RegisterFile(fd); err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	// The module runs the stamp interceptor every module behind a hop runs, so
	// the hop's reading of its declarations is proven to pass it.
	server := grpc.NewServer(grpc.ChainStreamInterceptor(hop.StreamServerInterceptor("run-proof")))
	reflectionv1.RegisterServerReflectionServer(server, reflection.NewServerV1(reflection.ServerOptions{
		DescriptorResolver: files, Services: served{"api.ApiService": {}},
	}))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///module",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type served map[string]grpc.ServiceInfo

func (s served) GetServiceInfo() map[string]grpc.ServiceInfo { return s }

func TestTheHopReadsEachMethodsPolicyFromTheModule(t *testing.T) {
	whoami := &hopv1.Policy{Requires: []*hopv1.Requirement{{ResourceKind: "console.identity", Actions: []string{"read"}}}}
	r := &policy.Reader{Module: module(t, map[string]*hopv1.Policy{"WhoAmI": whoami, "Version": {AnyCheckedCaller: true}})}
	ctx := context.Background()
	got, err := r.Policy(ctx, "/api.ApiService/WhoAmI")
	if err != nil || !proto.Equal(got, whoami) {
		t.Fatalf("WhoAmI: %v %v", got, err)
	}
	if got, err := r.Policy(ctx, "/api.ApiService/Version"); err != nil || !got.GetAnyCheckedCaller() {
		t.Fatalf("Version: %v %v", got, err)
	}
	if got, err := r.Policy(ctx, "/api.ApiService/Unmarked"); err != nil || got != nil {
		t.Fatalf("an unmarked method declares nothing: %v %v", got, err)
	}
	if _, err := r.Policy(ctx, "/api.ApiService/Missing"); !errors.Is(err, decide.ErrNoMethod) {
		t.Fatal("a method the module does not serve")
	}
	if _, err := r.Policy(ctx, "/other.Service/Method"); err == nil {
		t.Fatal("a service the module does not describe")
	}
}

func TestDeclarationsAreReadAgainOnceStale(t *testing.T) {
	now := time.Unix(0, 0)
	conn := module(t, map[string]*hopv1.Policy{"WhoAmI": {AnyCheckedCaller: true}})
	r := &policy.Reader{Module: conn, Now: func() time.Time { return now }}
	if _, err := r.Policy(context.Background(), "/api.ApiService/WhoAmI"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close() // the module went away: a fresh read still answers, a stale one asks again
	if _, err := r.Policy(context.Background(), "/api.ApiService/WhoAmI"); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	now = now.Add(policy.Fresh + time.Second)
	if _, err := r.Policy(context.Background(), "/api.ApiService/WhoAmI"); err == nil {
		t.Fatal("a stale read must ask the module again")
	}
}
