package decide_test

import (
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// modulePage is a module declaring a page and roles on what it serves.
func modulePage() domain.Module {
	return domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Generation: 1, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("pages.note", "read", "write")},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {sc("pages.note", "read", "write")},
			"viewer":             {sc("pages.note", "read")},
		}}
}

// A module that declares a page declares roles as a solution does, held to
// the same rules; a module without a page declares none, and a module page
// declaring none keeps the organization's roles.
func TestAModulePageDeclaresRolesLikeASolution(t *testing.T) {
	if err := decide.ValidateModule(modulePage()); err != nil {
		t.Fatalf("a module page declaring installer and viewer: %v", err)
	}
	headless := modulePage()
	headless.Page = false
	refused(t, decide.ValidateModule(headless), domain.Denied, "declares roles and no page")
	noInstaller := modulePage()
	delete(noInstaller.Roles, domain.InstallerRole)
	if err := decide.ValidateModule(noInstaller); !errors.Is(err, domain.ErrNoInstallerRole) {
		t.Fatalf("a module page with no installer role: %v", err)
	}
	beyond := modulePage()
	beyond.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "delete")}
	refused(t, decide.ValidateModule(beyond), domain.Denied, "grants beyond")
	owner := modulePage()
	owner.OwnedRoles = map[string][]*basev0.WorkScopeV1{"viewer": {sc("pages.note", "read")}}
	refused(t, decide.ValidateModule(owner), domain.Denied, "only a solution")
	bare := modulePage()
	bare.Roles = nil
	if err := decide.ValidateModule(bare); err != nil || decide.RoleGated(bare) {
		t.Fatalf("a module page declaring no roles keeps the organization's: %v, gated %v", err, decide.RoleGated(bare))
	}
	if !decide.RoleGated(modulePage()) {
		t.Fatal("a module page declaring roles is not decided by its roles")
	}
}

// A module page's installation has no principal: its roles select no owner.
func TestAModulePageRoleSelectsNoOwner(t *testing.T) {
	inst := domain.Installation{ID: "acme-pages", Organization: "acme"}
	got, err := decide.RoleScopes(modulePage(), inst, []string{"viewer"})
	if err != nil || !scope.Same(got, []*basev0.WorkScopeV1{sc("pages.note", "read")}) {
		t.Fatalf("viewer holds %v, %v", got, err)
	}
	if got, err := decide.RoleScopes(modulePage(), inst, []string{"undeclared"}); err != nil || len(got) != 0 {
		t.Fatalf("an undeclared role holds %v, %v", got, err)
	}
}

// Moving a module between the organization's roles and its own, either way,
// and cutting one of its roles are narrowings.
func TestAModulePageRoleChangeIsANarrowing(t *testing.T) {
	page, bare, cut := modulePage(), modulePage(), modulePage()
	bare.Roles = nil
	cut.Roles = map[string][]*basev0.WorkScopeV1{domain.InstallerRole: page.Roles[domain.InstallerRole], "viewer": nil}
	for name, c := range map[string]struct {
		previous, next domain.Module
		want           bool
	}{
		"roles declared":   {bare, page, true},
		"roles withdrawn":  {page, bare, true},
		"a role cut":       {page, cut, true},
		"unchanged":        {page, modulePage(), false},
		"a bare redeliver": {bare, bare, false},
	} {
		if got := decide.Narrowed(c.previous, c.next); got != c.want {
			t.Errorf("%s: narrowed %v, want %v", name, got, c.want)
		}
	}
}

// RBAC-1: a role-gated module's role scopes as another module receives them.
func TestRBAC1ModuleRoleAtSelectsTheInstallationAsOwner(t *testing.T) {
	read := func(kind string) *basev0.WorkScopeV1 {
		return &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{"read"}}
	}
	page := domain.Module{Name: "page", Principal: "page", Kind: domain.KindModule, Roles: map[string][]*basev0.WorkScopeV1{"viewer": {read("store.item")}}}
	solution := domain.Module{Name: "sol", Principal: "sol", Kind: domain.KindSolution}
	store := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, OwnerAware: true, SharedKinds: []string{"store.shared"}}
	blind := domain.Module{Name: "blind", Principal: "blind", Kind: domain.KindModule}
	selfAware := page
	selfAware.OwnerAware = true
	role := []*basev0.WorkScopeV1{read("store.item"), read("store.shared")}
	inst := domain.Installation{ID: "i", PrincipalID: "p-1"}
	for _, c := range []struct {
		name        string
		m, audience domain.Module
		inst        domain.Installation
		wantOwner   map[string]string // kind -> owner; absent: not held
	}{
		{"owner-aware audience: selected to the installation, shared unselected", page, store, inst, map[string]string{"store.item": "p-1", "store.shared": ""}},
		{"no principal: nothing owned, shared kept", page, store, domain.Installation{ID: "i"}, map[string]string{"store.shared": ""}},
		{"an audience checking no owner: unchanged", page, blind, inst, map[string]string{"store.item": "", "store.shared": ""}},
		{"the module itself: unchanged", page, selfAware, inst, map[string]string{"store.item": "", "store.shared": ""}},
		{"a solution's: already selected by RoleScopes, unchanged here", solution, store, inst, map[string]string{"store.item": "", "store.shared": ""}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := map[string]string{}
			for _, s := range decide.ModuleRoleAt(c.m, c.inst, c.audience, role) {
				got[s.GetResourceKind()] = s.GetResourceOwnerId()
			}
			if len(got) != len(c.wantOwner) {
				t.Fatalf("got %v, want %v", got, c.wantOwner)
			}
			for k, o := range c.wantOwner {
				if owner, ok := got[k]; !ok || owner != o {
					t.Fatalf("got %v, want %v", got, c.wantOwner)
				}
			}
		})
	}
}
