package hop

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAStampIsBelievedOnlyWithThisRunsProof(t *testing.T) {
	md := metadata.Pairs(OwnerKey, "mallory", ScopesKey, "documents:admin") // a caller's forged stamp
	Stamp(md, Identity{Owner: "maya", OwnerKind: "human", Tenant: "acme", Actors: []string{"org-directory"}, Scopes: []string{"documents:read"}}, "run-proof")
	id, err := Read(md, "run-proof")
	if err != nil || id.Owner != "maya" || len(id.Actors) != 1 || !id.Has("documents", "read") || id.Has("documents", "admin") {
		t.Fatalf("stamp: %+v %v", id, err)
	}
	if _, err := Read(md, "another-run"); err != ErrNoStamp {
		t.Fatalf("another run's proof: %v", err)
	}
	if _, err := Read(md, ""); err != ErrNoStamp {
		t.Fatalf("a module with no proof reads every call as bypassing the hop: %v", err)
	}
	if _, err := Read(metadata.Pairs(OwnerKey, "mallory", TenantKey, "acme"), "run-proof"); err != ErrNoStamp {
		t.Fatalf("a stamp without the proof: %v", err)
	}
}

func TestTheModuleRefusesACallThatBypassedTheHop(t *testing.T) {
	intercept := UnaryServerInterceptor("run-proof")
	handler := func(ctx context.Context, _ any) (any, error) {
		id, _ := FromContext(ctx)
		return id.Owner, nil
	}
	call := func(md metadata.MD, method string) (any, error) {
		return intercept(metadata.NewIncomingContext(context.Background(), md), nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	}
	if _, err := call(metadata.MD{}, "/api.ApiService/WhoAmI"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no stamp: %v", err)
	}
	md := metadata.MD{}
	Stamp(md, Identity{Owner: "maya", Tenant: "acme"}, "run-proof")
	if got, err := call(md, "/api.ApiService/WhoAmI"); err != nil || got != "maya" {
		t.Fatalf("stamped: %v %v", got, err)
	}
	if _, err := call(metadata.MD{}, "/grpc.health.v1.Health/Check"); err != nil {
		t.Fatalf("the run probes health directly: %v", err)
	}
	if _, err := call(metadata.MD{}, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("nothing but health passes unstamped: %v", err)
	}
	if _, err := call(metadata.MD{}, "/grpc.health.v1.HealthX/Check"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("only the named services pass: %v", err)
	}
}
