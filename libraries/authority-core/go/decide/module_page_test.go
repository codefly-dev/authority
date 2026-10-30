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
