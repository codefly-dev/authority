package composition

import (
	"context"
	"errors"
	"testing"

	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func consumedRoleDocument(consumed ...*authorityv1.WorkScopeV1) *compositionv1.AuthorityManifestV1 {
	own := scope("conformance.page", "read")
	return &compositionv1.AuthorityManifestV1{
		ScopeCeilings: []*authorityv1.WorkScopeV1{own},
		Roles: []*compositionv1.RoleV1{
			{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{own}},
			{Name: "operator", Scopes: append([]*authorityv1.WorkScopeV1{own}, consumed...)},
		},
	}
}

func consumedRoleBinding(binding solutionhost.AuthorityBinding) func(*solutionhost.ModuleManifest) {
	return func(m *solutionhost.ModuleManifest) {
		m.Authority.Bindings = []solutionhost.AuthorityBinding{binding}
		m.Workloads = []solutionhost.Workload{{Service: "conformance-solution", Container: "conformance-solution"}}
	}
}

func TestSignedSolutionRolesMayGrantOnlyDeclaredPersonOperations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		operations map[string][]string
		grant      *authorityv1.WorkScopeV1
		allowed    bool
	}{
		{"invoke", map[string][]string{"invoke": {"documents:write"}}, scope("documents", "write"), true},
		{"lookup with headless", map[string][]string{"headless": {"documents:read", "documents:write"}, "lookup": {"documents:read"}}, scope("documents", "read"), true},
		{"headless alone", map[string][]string{"headless": {"documents:write"}}, scope("documents", "write"), false},
		{"undeclared kind", map[string][]string{"invoke": {"documents:read"}}, scope("records.records", "read"), false},
		{"undeclared action", map[string][]string{"invoke": {"documents:read"}}, scope("documents", "write"), false},
		{"lookup cannot borrow headless write", map[string][]string{"headless": {"documents:read", "documents:write"}, "lookup": {"documents:read"}}, scope("documents", "write"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, k := verifying(t)
			binding := solutionhost.AuthorityBinding{ID: "documents", Audience: "documents", Operations: tc.operations}
			req := carrier(t, k, "conformance-solution", solutionhost.KindSolution, 1, []string{"conformance.page"}, consumedRoleDocument(tc.grant), consumedRoleBinding(binding))
			_, err := p.ApplyManifest(context.Background(), req)
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("invalid role admitted: %v", err)
				}
				if _, err := k.State.ModuleByPrincipal("conformance-solution"); !errors.Is(err, state.ErrUnknown) {
					t.Fatalf("refused delivery changed state: %v", err)
				}
			}
		})
	}
}
