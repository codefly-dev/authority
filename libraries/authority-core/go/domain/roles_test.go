package domain_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
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

// The grant crossover of the same stopgap, least privilege: when the next
// declaration is exactly admin and user, installer moves to admin and every
// other old role (editor, viewer, steward) to user, whatever it held. Nothing
// else ever moves, and nothing moves beside a third role.
func TestTheOldRolesCrossOverPlainlyForOneRelease(t *testing.T) {
	two := map[string]bool{"admin": true, "user": true}
	for _, c := range []struct {
		name, role  string
		next        map[string]bool
		want, basis string
		ok          bool
	}{
		{"the installer", "installer", two, "admin", domain.BasisInstaller, true},
		{"an editor", "editor", two, "user", domain.BasisLegacyToUser, true},
		{"a viewer", "viewer", two, "user", domain.BasisLegacyToUser, true},
		{"a steward", "steward", two, "user", domain.BasisLegacyToUser, true},
		{"a third role kept beside the two", "editor", map[string]bool{"admin": true, "user": true, "auditor": true}, "", "", false},
		{"no user declared", "viewer", map[string]bool{"admin": true}, "", "", false},
		{"installer beside its alias", "installer", map[string]bool{"installer": true, "user": true}, "", "", false},
		{"a role that is no old name", "author", two, "", "", false},
		{"user itself", "user", two, "", "", false},
	} {
		if got, basis, ok := domain.CrossoverRole(c.role, c.next); got != c.want || basis != c.basis || ok != c.ok {
			t.Errorf("%s: CrossoverRole(%q) = %q %q %v, want %q %q %v", c.name, c.role, got, basis, ok, c.want, c.basis, c.ok)
		}
	}
}

// The crossover is named among what an update asks, one line per old role
// the approved declaration names, only for the two-role declaration.
func TestTheCrossoverIsNamedForReview(t *testing.T) {
	old := map[string]bool{"installer": true, "editor": true, "steward": true, "author": true}
	got := domain.Crossovers(old, map[string]bool{"admin": true, "user": true})
	want := []string{"holders of role editor move to user", "holders of role installer move to admin", "holders of role steward move to user"}
	if !slices.Equal(got, want) {
		t.Fatalf("Crossovers = %v, want %v", got, want)
	}
	if got := domain.Crossovers(old, map[string]bool{"admin": true, "user": true, "author": true}); got != nil {
		t.Fatalf("a declaration beside a third role names a crossover: %v", got)
	}
}
