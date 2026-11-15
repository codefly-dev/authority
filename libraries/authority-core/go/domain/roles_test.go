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
