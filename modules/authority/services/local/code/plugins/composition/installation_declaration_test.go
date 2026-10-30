package composition

import (
	"context"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Uses generated messages, both real signatures and actual ApplyManifest
// persistence. CLI producer construction is qualified by the CLI owner.
func TestSignedInstallationDeclarationsReachStoredModule(t *testing.T) {
	for _, selector := range []string{"", "none", "editor"} {
		t.Run(selector, func(t *testing.T) {
			p, k := verifying(t)
			req := carrier(t, k, "wiki", solutionhost.KindSolution, 2, []string{"wiki.page"}, installationDocument(selector), installationManifest(selector))
			if _, err := p.ApplyManifest(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			got, ok := k.State.Module("wiki")
			if !ok || got.InstallationRole != selector || len(got.EdgeDependencies) != 2 || got.EdgeDependencies[0].Module != "z-principal" || got.EdgeDependencies[1].Module != "a-principal" || got.EdgeDependencies[0].Presence != "required" || got.EdgeDependencies[1].Presence != "optional" {
				t.Fatalf("stored declaration: %+v", got)
			}
		})
	}
}

func installationDocument(selector string) *compositionv1.AuthorityManifestV1 {
	page := scope("wiki.page", "read", "write")
	return &compositionv1.AuthorityManifestV1{InstallationRole: selector, EdgeDependencies: []*compositionv1.EdgeDependencyV1{{Module: "z-principal", Presence: "required"}, {Module: "a-principal", Presence: "optional"}}, ScopeCeilings: []*authorityv1.WorkScopeV1{page}, Roles: []*compositionv1.RoleV1{{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{page}}, {Name: "editor", Scopes: []*authorityv1.WorkScopeV1{page}}}}
}

func installationManifest(selector string) func(*solutionhost.ModuleManifest) {
	return func(m *solutionhost.ModuleManifest) {
		m.Authority.InstallationRole = selector
		m.Authority.EdgeDependencies = []modulecontract.EdgeDependency{{Module: "z-principal", Presence: "required"}, {Module: "a-principal", Presence: "optional"}}
	}
}

func TestSignedInstallationDeclarationDisagreementRefusesBeforeStore(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		change      func(**compositionv1.AuthorityManifestV1)
	}{
		{"selector", "installation_role", func(d **compositionv1.AuthorityManifestV1) { (*d).InstallationRole = "editor" }},
		{"selector omitted", "installation_role", func(d **compositionv1.AuthorityManifestV1) { (*d).InstallationRole = "" }},
		{"sidecar absent", "installation_role", func(d **compositionv1.AuthorityManifestV1) { *d = nil }},
		{"edge identity", "edge_dependencies", func(d **compositionv1.AuthorityManifestV1) { (*d).EdgeDependencies[0].Module = "route-alias" }},
		{"edge presence", "edge_dependencies", func(d **compositionv1.AuthorityManifestV1) { (*d).EdgeDependencies[0].Presence = "optional" }},
		{"edge order", "edge_dependencies", func(d **compositionv1.AuthorityManifestV1) {
			(*d).EdgeDependencies[0], (*d).EdgeDependencies[1] = (*d).EdgeDependencies[1], (*d).EdgeDependencies[0]
		}},
		{"edges omitted", "edge_dependencies", func(d **compositionv1.AuthorityManifestV1) { (*d).EdgeDependencies = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, k := verifying(t)
			before, _ := k.State.Module("wiki")
			doc := installationDocument("none")
			tc.change(&doc)
			// The mismatching sidecar is correctly signed and pins the carrier.
			req := carrier(t, k, "wiki", solutionhost.KindSolution, 2, []string{"wiki.page"}, doc, installationManifest("none"))
			_, err := p.ApplyManifest(context.Background(), req)
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("mismatch: %v", err)
			}
			after, _ := k.State.Module("wiki")
			if after.Generation != before.Generation {
				t.Fatal("refused declaration persisted")
			}
		})
	}
}
