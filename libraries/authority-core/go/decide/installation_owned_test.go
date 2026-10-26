package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func ownedModule() domain.Module {
	sc := &basev0.WorkScopeV1{ResourceKind: "collection", Actions: []string{"read"}}
	return domain.Module{Name: "solution", Principal: "solution", Kind: domain.KindSolution, Generation: 1,
		Bindings:   map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc}}},
		Roles:      map[string][]*basev0.WorkScopeV1{domain.InstallerRole: nil},
		OwnedRoles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: {sc}},
	}
}

func TestInstallationOwnedDeclarationRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*domain.Module)
	}{
		{"ids", "names resource ids", func(m *domain.Module) { m.OwnedRoles[domain.InstallerRole][0].ResourceIds = []string{"x"} }},
		{"owner", "names resource ids or an owner", func(m *domain.Module) { m.OwnedRoles[domain.InstallerRole][0].ResourceOwnerId = "owner" }},
		{"undeclared", "not declared", func(m *domain.Module) { m.OwnedRoles["missing"] = m.OwnedRoles[domain.InstallerRole] }},
		{"ceiling", "beyond", func(m *domain.Module) { m.Bindings = nil }},
		{"module", "only a solution", func(m *domain.Module) { m.Kind = domain.KindModule }},
		{"empty", "grants nothing", func(m *domain.Module) { m.OwnedRoles = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := ownedModule()
			tc.change(&m)
			err := decide.ValidateModule(m)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("want %q: %v", tc.reason, err)
			}
		})
	}
	if err := decide.ValidateModule(ownedModule()); err != nil {
		t.Fatalf("owned-only role: %v", err)
	}
}

func TestInstallationOwnedResolutionNeverEmitsAnEmptyIDGrant(t *testing.T) {
	m := ownedModule()
	inst := domain.Installation{ID: "installation", PrincipalID: "principal"}
	got, err := decide.RoleScopes(m, inst, []string{domain.InstallerRole})
	if err != nil || len(got) != 0 {
		t.Fatalf("owns nothing: %v %v", got, err)
	}
	inst.Owned = map[string][]string{"collection": {"x"}}
	got, err = decide.RoleScopes(m, inst, []string{domain.InstallerRole})
	if err != nil || len(got) != 1 || len(got[0].ResourceIds) != 1 || got[0].ResourceIds[0] != "x" || got[0].ResourceOwnerId != "" {
		t.Fatalf("exact attached id: %v %v", got, err)
	}
	got[0].ResourceIds[0] = "mutated"
	if inst.Owned["collection"][0] != "x" {
		t.Fatal("resolution mutated the installation")
	}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{{ResourceKind: "note", Actions: []string{"read"}}}
	got, err = decide.RoleScopes(m, inst, []string{domain.InstallerRole})
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range got {
		if sc.ResourceKind == "note" && sc.ResourceOwnerId != "principal" {
			t.Fatal("ordinary roles lost owner selection")
		}
	}
	next := ownedModule()
	next.OwnedRoles = nil
	if !decide.Narrowed(m, next) {
		t.Fatal("withdrawing owned roles must invalidate capabilities")
	}
}
