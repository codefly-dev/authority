package domain_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The admin role is "admin". For one release its legacy name "installer" is
// an alias of it (domain.LegacyInstallerRole), and nothing else is: neither
// "editor" nor "viewer" stands for any role. This test pins the alias, so
// deleting it in the next release means deleting this case on purpose.
func TestTheLegacyInstallerIsTheAdminRoleForOneRelease(t *testing.T) {
	if domain.AdminRole != "admin" || domain.UserRole != "user" || domain.LegacyInstallerRole != "installer" {
		t.Fatalf("roles %q %q %q", domain.AdminRole, domain.UserRole, domain.LegacyInstallerRole)
	}
	for role, admin := range map[string]bool{"admin": true, "installer": true, "user": false, "editor": false, "viewer": false, "": false} {
		if got := domain.IsAdminRole(role); got != admin {
			t.Errorf("IsAdminRole(%q) = %v, want %v", role, got, admin)
		}
		if got := domain.HoldsAdmin([]string{"user", role}); got != admin {
			t.Errorf("HoldsAdmin(user, %q) = %v, want %v", role, got, admin)
		}
	}
	for _, c := range []struct {
		declared []string
		want     string
		ok       bool
	}{
		{[]string{"admin", "user"}, "admin", true},
		{[]string{"installer", "user"}, "installer", true},
		{[]string{"admin", "installer"}, "admin", true},
		{[]string{"editor", "viewer", "user"}, "", false},
	} {
		roles := map[string]bool{}
		for _, r := range c.declared {
			roles[r] = true
		}
		if got, ok := domain.DeclaredAdminRole(roles); got != c.want || ok != c.ok {
			t.Errorf("DeclaredAdminRole(%v) = %q %v, want %q %v", c.declared, got, ok, c.want, c.ok)
		}
	}
}

// The grant crossover of the same stopgap: a grant of an old person role
// moves, when the next declaration is exactly admin and user, to the
// narrowest new role whose scopes cover what the old role declared:
// installer always to admin; a viewer, an editor or a steward to user when
// user covers it, otherwise to admin, so nobody loses access. Nothing else ever moves.
func TestTheOldRolesCrossOverToTheNarrowestCoveringRoleForOneRelease(t *testing.T) {
	ws := func(actions ...string) []*basev0.WorkScopeV1 {
		return []*basev0.WorkScopeV1{{ResourceKind: "wiki.page", Actions: actions}}
	}
	old := map[string][]*basev0.WorkScopeV1{"installer": ws("read", "write", "publish"), "editor": ws("read", "write"), "viewer": ws("read"),
		"steward": {{ResourceKind: "records.types", Actions: []string{"define", "read"}}}}
	directory := map[string][]*basev0.WorkScopeV1{
		"admin": {{ResourceKind: "records.types", Actions: []string{"define", "read"}}, {ResourceKind: "wiki.page", Actions: []string{"read", "write"}}},
		"user":  {{ResourceKind: "records.types", Actions: []string{"read"}}, {ResourceKind: "wiki.page", Actions: []string{"read", "write"}}}}
	readingUser := map[string][]*basev0.WorkScopeV1{"admin": ws("read", "write", "publish"), "user": ws("read")}
	writingUser := map[string][]*basev0.WorkScopeV1{"admin": ws("read", "write", "publish"), "user": ws("read", "write")}
	for _, c := range []struct {
		name, role string
		next       map[string][]*basev0.WorkScopeV1
		want       string
		ok         bool
	}{
		{"a viewer, where user reads", "viewer", readingUser, "user", true},
		{"an editor whose writes user covers", "editor", writingUser, "user", true},
		{"an editor whose writes only admin covers", "editor", readingUser, "admin", true},
		{"the installer", "installer", readingUser, "admin", true},
		{"a steward, whose define user does not cover", "steward", directory, "admin", true},
		{"a viewer, on the directory", "viewer", directory, "user", true},
		{"the installer, where user writes", "installer", writingUser, "admin", true},
		{"a third role kept beside the two", "editor", map[string][]*basev0.WorkScopeV1{"admin": ws("read"), "user": ws("read"), "auditor": ws("read")}, "", false},
		{"no user declared", "viewer", map[string][]*basev0.WorkScopeV1{"admin": ws("read")}, "", false},
		{"a role that is no old name", "author", readingUser, "", false},
		{"user itself", "user", readingUser, "", false},
	} {
		if got, ok := domain.CrossoverRole(c.role, old, c.next); got != c.want || ok != c.ok {
			t.Errorf("%s: CrossoverRole(%q) = %q %v, want %q %v", c.name, c.role, got, ok, c.want, c.ok)
		}
	}
	// What an editor held is unknown when the approved declaration does not
	// name it: nothing proves a covering role, so it does not move.
	if got, ok := domain.CrossoverRole("editor", nil, writingUser); ok {
		t.Errorf("an editor with no approved scopes moved to %q", got)
	}
}

// The crossover is named among what an update asks, one line per old role
// the approved declaration names, only for the two-role declaration.
func TestTheCrossoverIsNamedForReview(t *testing.T) {
	ws := func(actions ...string) []*basev0.WorkScopeV1 {
		return []*basev0.WorkScopeV1{{ResourceKind: "wiki.page", Actions: actions}}
	}
	old := map[string][]*basev0.WorkScopeV1{"installer": ws("read", "write"), "editor": ws("read", "write"), "viewer": ws("read"), "author": ws("read")}
	got := domain.Crossovers(old, map[string][]*basev0.WorkScopeV1{"admin": ws("read", "write"), "user": ws("read")})
	want := []string{"holders of role editor move to admin", "holders of role installer move to admin", "holders of role viewer move to user"}
	if !slices.Equal(got, want) {
		t.Fatalf("Crossovers = %v, want %v", got, want)
	}
	if got := domain.Crossovers(old, map[string][]*basev0.WorkScopeV1{"admin": ws("read"), "user": ws("read"), "author": ws("read")}); got != nil {
		t.Fatalf("a declaration beside a third role names a crossover: %v", got)
	}
}
