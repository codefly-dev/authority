package domain_test

import (
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

// The grant crossover of the same stopgap: a grant of an old person role the
// next declaration no longer declares moves to its successor, when that is
// declared: installer to admin, editor and viewer to user. A role still
// declared, or one with no declared successor, does not move, and nothing
// else ever does.
func TestTheOldRolesCrossOverToTheTwoForOneRelease(t *testing.T) {
	two := map[string]bool{"admin": true, "user": true}
	for _, c := range []struct {
		role     string
		declared map[string]bool
		want     string
		ok       bool
	}{
		{"installer", two, "admin", true},
		{"editor", two, "user", true},
		{"viewer", two, "user", true},
		{"viewer", map[string]bool{"admin": true}, "", false},
		{"viewer", map[string]bool{"admin": true, "user": true, "viewer": true}, "", false},
		{"installer", map[string]bool{"installer": true, "user": true}, "", false},
		{"author", two, "", false},
		{"user", two, "", false},
	} {
		if got, ok := domain.CrossoverRole(c.role, c.declared); got != c.want || ok != c.ok {
			t.Errorf("CrossoverRole(%q, %v) = %q %v, want %q %v", c.role, c.declared, got, ok, c.want, c.ok)
		}
	}
}
