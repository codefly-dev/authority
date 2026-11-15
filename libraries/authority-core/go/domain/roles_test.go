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
// user covers it, otherwise to admin, and to user when what it declared is
// unknown, so nobody loses access. Nothing else ever moves.
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
		name, role  string
		approved    map[string][]*basev0.WorkScopeV1
		next        map[string][]*basev0.WorkScopeV1
		want, basis string
		ok          bool
	}{
		{"a viewer, where user reads", "viewer", old, readingUser, "user", domain.BasisCoverage, true},
		{"an editor whose writes user covers", "editor", old, writingUser, "user", domain.BasisCoverage, true},
		{"an editor whose writes only admin covers", "editor", old, readingUser, "admin", domain.BasisCoverage, true},
		{"the installer", "installer", old, readingUser, "admin", domain.BasisInstaller, true},
		{"a steward, whose define user does not cover", "steward", old, directory, "admin", domain.BasisCoverage, true},
		{"a viewer, on the directory", "viewer", old, directory, "user", domain.BasisCoverage, true},
		{"the installer, where user writes", "installer", old, writingUser, "admin", domain.BasisInstaller, true},
		{"an editor under an unknown declaration", "editor", nil, readingUser, "user", domain.BasisUnknownDeclaration, true},
		{"a steward under an unknown declaration", "steward", nil, directory, "user", domain.BasisUnknownDeclaration, true},
		{"the installer under an unknown declaration", "installer", nil, readingUser, "admin", domain.BasisInstaller, true},
		{"a third role kept beside the two", "editor", old, map[string][]*basev0.WorkScopeV1{"admin": ws("read"), "user": ws("read"), "auditor": ws("read")}, "", "", false},
		{"no user declared", "viewer", old, map[string][]*basev0.WorkScopeV1{"admin": ws("read")}, "", "", false},
		{"a role that is no old name", "author", old, readingUser, "", "", false},
		{"user itself", "user", old, readingUser, "", "", false},
	} {
		if got, basis, ok := domain.CrossoverRole(c.role, c.approved, c.next); got != c.want || basis != c.basis || ok != c.ok {
			t.Errorf("%s: CrossoverRole(%q) = %q %q %v, want %q %q %v", c.name, c.role, got, basis, ok, c.want, c.basis, c.ok)
		}
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
