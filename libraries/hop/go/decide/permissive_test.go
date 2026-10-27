package decide

import (
	"context"
	"errors"

	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// unsound is the authority refusing the Work Context itself: verification, not
// the method's policy, so even an advisory Check refuses it.
type unsound struct{}

func (unsound) Check(context.Context, *authorityv1.CheckRequest, ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	return nil, status.Error(codes.Unauthenticated, "the Work Context's signature does not verify")
}

// Permissive or not, a call whose identity the authority could not establish is
// refused: a missing, ambiguous or undecodable Work Context, one addressed to a
// module the hop does not front, one the authority refuses as unsound, and one
// the authority could not be asked about. Nothing is stamped as a developer.
func TestHopRefusesWhatHasNoSoundIdentity(t *testing.T) {
	audience := func(string) (string, error) { return "robin", nil }
	undecodable := func(string) (string, error) { return "", errors.New("not a Work Context") }
	for _, tc := range []struct {
		name string
		d    Decider
		md   metadata.MD
		code codes.Code
	}{
		{"no work context", Decider{Authority: advisoryChecker{}, AudienceOf: audience}, nil, codes.Unauthenticated},
		{"two work contexts", Decider{Authority: advisoryChecker{}, AudienceOf: audience}, metadata.Pairs(hop.WorkContextKey, "a", hop.WorkContextKey, "b"), codes.InvalidArgument},
		{"undecodable", Decider{Authority: advisoryChecker{}, AudienceOf: undecodable}, metadata.Pairs(hop.WorkContextKey, "x"), codes.Unauthenticated},
		{"not fronted", Decider{Authority: advisoryChecker{}, AudienceOf: func(string) (string, error) { return "documents", nil }}, metadata.Pairs(hop.WorkContextKey, "x"), codes.PermissionDenied},
		{"unsound", Decider{Authority: unsound{}, AudienceOf: audience}, metadata.Pairs(hop.WorkContextKey, "x"), codes.Unauthenticated},
		{"authority unreachable", Decider{Authority: unreachable{}, AudienceOf: audience}, metadata.Pairs(hop.WorkContextKey, "x"), codes.Unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := tc.d
			d.Routes = testRoutes("robin", "GET /v1/robin/intents/version")
			d.Modules = map[string]bool{"robin": true}
			decision, err := d.Decide(context.Background(), "GET /v1/robin/intents/version", tc.md)
			module, id := decision.Module, decision.Identity
			if status.Code(err) != tc.code || module != "" || id.Owner != "" {
				t.Fatalf("module=%q id=%+v error=%v; want refused %v", module, id, err, tc.code)
			}
		})
	}
}

type unreachable struct{}

func (unreachable) Check(context.Context, *authorityv1.CheckRequest, ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	return nil, status.Error(codes.Unavailable, "connection refused")
}

// The gateway already provides verified identity with an advisory. The hop
// must use that answer, including the binding and attenuated actor scopes.
type advisoryChecker struct{}

func (advisoryChecker) Check(_ context.Context, req *authorityv1.CheckRequest, _ ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	if !req.GetAdvisory() {
		return nil, status.Error(codes.PermissionDenied, "write scope missing")
	}
	return &authorityv1.CheckResponse{Refusal: "write scope missing", Context: &authorityv1.WorkContextV1{
		OwnerPrincipalId: "maya", OwnerPrincipalKind: proto.String("human"), TenantId: "acme", TaskId: "task-1", ExpiresAtUnix: 42,
		OperationBinding: &authorityv1.WorkOperationBindingV1{BindingId: "acme/robin/documents"},
		AuthorityScopes:  []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read", "write"}}},
		ActorChain:       []*authorityv1.WorkActorV1{{PrincipalId: "robin", GrantedScopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}}}}},
	}}, nil
}

// A policy refusal can never become a signed downstream admission.
func TestPolicyRefusalStopsBeforeStamping(t *testing.T) {
	strict := Decider{Routes: testRoutes("documents", "POST /documents/write"), Authority: advisoryChecker{}, Modules: map[string]bool{"documents": true}, AudienceOf: func(string) (string, error) { return "documents", nil }}
	if _, err := strict.Decide(context.Background(), "POST /documents/write", metadata.Pairs(hop.WorkContextKey, "test-context")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("policy refusal: %v", err)
	}
}

func testRoutes(audience, method string) *routing.Routing {
	return &routing.Routing{Endpoints: []routing.RouteEndpoint{{Audience: audience, Transport: "http", Address: "unused", Methods: []string{method}}}}
}
