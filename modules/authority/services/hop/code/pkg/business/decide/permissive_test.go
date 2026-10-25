package decide

import (
	"context"
	"strings"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type refusing struct{}

func (refusing) Check(context.Context, *authorityv1.CheckRequest, ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "robin requires robin.intents:read_config for GET /v1/robin/intents/version, which the call does not hold")
}

// Permissive, the hop lets a refused call through: the module is the token's
// audience, the identity what the token claims, the refusal rides as the
// stamp's advisory and is told to Warned. Enforcing, the refusal stands.
func TestAPermissiveHopLetsARefusedCallThroughWithTheRefusalAsAdvisory(t *testing.T) {
	var warned string
	d := Decider{Authority: refusing{}, Modules: map[string]bool{"robin": true}, Permissive: true,
		Warned:     func(method string, err error) { warned = method + ": " + err.Error() },
		AudienceOf: func(string) (string, error) { return "robin", nil }}
	md := metadata.Pairs(hop.WorkContextKey, "not-a-core-token")
	module, id, err := d.Decide(context.Background(), "GET /v1/robin/intents/version", md)
	if err != nil || module != "robin" {
		t.Fatalf("permissive: %v %v", module, err)
	}
	if id.Owner != "developer" || id.Tenant != "local" || id.Advisory == "" {
		t.Fatalf("an undecodable token is stamped as a developer with the advisory: %+v", id)
	}
	if warned == "" {
		t.Fatal("the refusal was not told")
	}
	stamp := metadata.MD{}
	hop.Stamp(stamp, id, "proof")
	read, err := hop.Read(stamp, "proof")
	if err != nil || read.Advisory != id.Advisory {
		t.Fatalf("the advisory rides the stamp: %+v %v", read, err)
	}

	strict := Decider{Authority: refusing{}, Modules: map[string]bool{"robin": true}, AudienceOf: func(string) (string, error) { return "robin", nil }}
	if _, _, err := strict.Decide(context.Background(), "GET /v1/robin/intents/version", md); err == nil || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("enforcing, the refusal stands: %v", err)
	}
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

func TestPermissivePolicyUsesTheAuthorityAdvisoryIdentity(t *testing.T) {
	warnings := 0
	d := Decider{Authority: advisoryChecker{}, Modules: map[string]bool{"documents": true}, Permissive: true,
		AudienceOf: func(string) (string, error) { return "documents", nil },
		Warned: func(method string, err error) {
			warnings++
			if method != "POST /documents/write" || status.Convert(err).Message() != "write scope missing" {
				t.Errorf("warning = %q, %v", method, err)
			}
		},
	}
	module, id, err := d.Decide(context.Background(), "POST /documents/write", metadata.Pairs(hop.WorkContextKey, "test-context"))
	if err != nil || module != "documents" || warnings != 1 {
		t.Fatalf("decision = %q, %v; warnings = %d", module, err, warnings)
	}
	if id.Owner != "maya" || id.Tenant != "acme" || id.Binding != "acme/robin/documents" || id.Task != "task-1" || id.Expires != 42 {
		t.Fatalf("lost authority identity: %+v", id)
	}
	if id.Advisory != "write scope missing" || len(id.Actors) != 1 || id.Actors[0] != "robin" || len(id.Scopes) != 1 || id.Scopes[0] != "documents:read" {
		t.Fatalf("lost advisory or effective scopes: %+v", id)
	}
}

func TestPermissiveFallbackNeedsAnUnambiguousDestination(t *testing.T) {
	for _, tc := range []struct {
		name       string
		modules    map[string]bool
		code       codes.Code
		diagnostic string
		module     string
		warnings   int
	}{
		{name: "none", modules: map[string]bool{}, code: codes.Internal, diagnostic: "fronts no module"},
		{name: "sole upstream", modules: map[string]bool{"records": true, "documents": false}, code: codes.OK, module: "records", warnings: 1},
		{name: "unresolved audience", modules: map[string]bool{"records": true, "documents": true}, code: codes.FailedPrecondition, diagnostic: "without a module audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings := 0
			d := Decider{Permissive: true, Modules: tc.modules, Warned: func(string, error) { warnings++ }}
			module, _, err := d.Decide(context.Background(), "/records.v1.RecordsService/ReadRecord", nil)
			if module != tc.module || status.Code(err) != tc.code || warnings != tc.warnings {
				t.Fatalf("module=%q error=%v warnings=%d; want %q %v %d", module, err, warnings, tc.module, tc.code, tc.warnings)
			}
			if tc.diagnostic != "" && !strings.Contains(status.Convert(err).Message(), tc.diagnostic) {
				t.Fatalf("missing routing diagnostic %q: %v", tc.diagnostic, err)
			}
		})
	}
}
