package decide_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// STOPGAP, one release: a page or solution still declaring "installer" in
// place of "admin" validates, and a holder of "installer" administers the
// installation's grants. "editor" and "viewer" stand for nothing: a
// declaration of only those is refused, and their holders administer
// nothing. Delete with domain.LegacyInstallerRole.
func TestTheLegacyInstallerStandsForTheAdminRoleForOneRelease(t *testing.T) {
	page := func(roles ...string) domain.Module {
		m := domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Generation: 1, Page: true,
			ResourceKinds: []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, Roles: map[string][]*basev0.WorkScopeV1{}}
		for _, r := range roles {
			m.Roles[r] = []*basev0.WorkScopeV1{sc("pages.note", "read")}
		}
		return m
	}
	for _, roles := range [][]string{{"admin", "user"}, {"installer", "user"}, {"installer", "editor", "viewer"}} {
		if err := decide.ValidateModule(page(roles...)); err != nil {
			t.Errorf("a page declaring %v: %v", roles, err)
		}
	}
	if err := decide.ValidateModule(page("editor", "viewer")); !errors.Is(err, domain.ErrNoAdminRole) {
		t.Errorf("a page declaring editor and viewer alone: want ErrNoAdminRole, got %v", err)
	}
	// Both names would be two admin-powered roles: refused.
	if err := decide.ValidateModule(page("admin", "installer", "user")); err == nil || !strings.Contains(err.Error(), `declares both "admin" and "installer"`) {
		t.Errorf("a page declaring admin and installer: want a refusal naming both, got %v", err)
	}
	solution := page("admin", "installer")
	solution.Kind, solution.Page = domain.KindSolution, false
	if err := decide.ValidateModule(solution); err == nil {
		t.Error("a solution declaring admin and installer validated")
	}

	inst := domain.Installation{ID: "inst-1", Organization: "acme", Target: "pages", Status: domain.Active}
	member := domain.Person{ID: "dev", Organization: "acme"}
	change := func(held ...string) decide.RoleChange {
		return decide.RoleChange{RequestOrganization: "acme", RequestedID: inst.ID, Installation: inst, Solution: page("installer", "user"),
			Caller: member, CallerRoles: held, Role: "user", PersonID: "dev", Subject: &member}
	}
	for _, held := range []string{"admin", "installer"} {
		if err := decide.ChangeRole(change(held)); err != nil {
			t.Errorf("a holder of %q grants: %v", held, err)
		}
	}
	for _, held := range []string{"user", "editor", "viewer"} {
		if err := decide.ChangeRole(change(held)); err == nil {
			t.Errorf("a holder of %q granted", held)
		}
	}
}
