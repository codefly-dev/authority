package decide_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The roles are admin and user. A declaration naming "installer" in place of
// "admin" declares no admin role; one naming any other role beside the two is
// refused by that name; a holder of a role named anything else administers
// nothing and holds nothing; and no role but the two is granted, whatever a
// declaration the core still holds names.
func TestOnlyAdminAndUserAreRoles(t *testing.T) {
	page := func(roles ...string) domain.Module {
		m := domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Generation: 1, Page: true,
			ResourceKinds: []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}, Roles: map[string][]*basev0.WorkScopeV1{}}
		for _, r := range roles {
			m.Roles[r] = []*basev0.WorkScopeV1{sc("pages.note", "read")}
		}
		return m
	}
	both := func(m domain.Module) error {
		if err := decide.ValidateModule(m); err != nil {
			return err
		}
		return decide.PageRoles(m)
	}
	if err := both(page("admin", "user")); err != nil {
		t.Errorf("a page declaring admin and user: %v", err)
	}
	for _, roles := range [][]string{{"installer", "user"}, {"installer", "editor", "viewer"}, {"editor", "viewer"}} {
		if err := decide.ValidateModule(page(roles...)); !errors.Is(err, domain.ErrNoAdminRole) {
			t.Errorf("a page declaring %v: want ErrNoAdminRole, got %v", roles, err)
		}
	}
	for _, name := range []string{"installer", "editor", "viewer", "steward", "author"} {
		want := `declares role "` + name + `", which is neither "admin" nor "user"`
		if err := both(page("admin", "user", name)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("a page declaring admin, user and %s: want a refusal naming %q, got %v", name, want, err)
		}
		solution := page("admin", "user", name)
		solution.Kind, solution.Page = domain.KindSolution, false
		if err := both(solution); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("a solution declaring admin, user and %s: want a refusal naming %q, got %v", name, want, err)
		}
	}

	inst := domain.Installation{ID: "inst-1", Organization: "acme", Target: "pages", Status: domain.Active}
	member := domain.Person{ID: "dev", Organization: "acme"}
	// A declaration the core holds from before, naming the old roles.
	held := page("installer", "editor", "viewer", "user")
	change := func(role string, callerRoles ...string) decide.RoleChange {
		return decide.RoleChange{RequestOrganization: "acme", RequestedID: inst.ID, Installation: inst, Solution: held,
			Caller: member, CallerRoles: callerRoles, Role: role, PersonID: "dev", Subject: &member}
	}
	if err := decide.ChangeRole(change("user", "admin")); err != nil {
		t.Errorf("a holder of admin grants user: %v", err)
	}
	for _, name := range []string{"installer", "user", "editor", "viewer", "steward"} {
		if err := decide.ChangeRole(change("user", name)); err == nil {
			t.Errorf("a holder of %q granted", name)
		}
	}
	for _, name := range []string{"installer", "editor", "viewer"} {
		want := `role "` + name + `" is neither "admin" nor "user"`
		if err := decide.ChangeRole(change(name, "admin")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("granting %s, which the held declaration names: want a refusal naming %q, got %v", name, want, err)
		}
	}

	grants := []domain.RoleGrant{
		{InstallationID: inst.ID, Role: "installer", PersonID: "dev"}, {InstallationID: inst.ID, Role: "editor", PersonID: "dev"},
		{InstallationID: inst.ID, Role: "viewer", TeamID: "team"}, {InstallationID: inst.ID, Role: "steward", TeamID: "team"},
	}
	who := domain.Person{ID: "dev", Organization: "acme", Teams: []string{"team"}}
	if got := decide.HeldRoles(who, inst, grants); len(got) != 0 {
		t.Errorf("grants of roles named neither admin nor user are held as %v, want nothing", got)
	}
	if got := decide.HeldRoles(domain.Person{ID: "dev", Organization: "acme", Cast: "team"}, inst, grants); len(got) != 0 {
		t.Errorf("a cast onto a team granted roles named neither admin nor user holds %v, want nothing", got)
	}
	grants = append(grants, domain.RoleGrant{InstallationID: inst.ID, Role: "user", TeamID: "team"})
	if got := decide.HeldRoles(who, inst, grants); len(got) != 1 || got[0] != "user" {
		t.Errorf("held %v, want user alone", got)
	}
}
