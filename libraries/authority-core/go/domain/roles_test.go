package domain_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// The roles a person holds on a solution or a module page are "admin" and
// "user", and nothing else is one: no former name ("installer", "editor",
// "viewer", "steward") stands for either, and only "admin" administers.
func TestAdminAndUserAreTheOnlyRoles(t *testing.T) {
	if domain.AdminRole != "admin" || domain.UserRole != "user" {
		t.Fatalf("roles %q %q", domain.AdminRole, domain.UserRole)
	}
	for role, c := range map[string]struct{ role, admin bool }{
		"admin": {true, true}, "user": {true, false},
		"installer": {}, "editor": {}, "viewer": {}, "steward": {}, "owner": {}, "": {},
	} {
		if got := domain.IsRole(role); got != c.role {
			t.Errorf("IsRole(%q) = %v, want %v", role, got, c.role)
		}
		if got := domain.IsAdminRole(role); got != c.admin {
			t.Errorf("IsAdminRole(%q) = %v, want %v", role, got, c.admin)
		}
		if got := domain.HoldsAdmin([]string{"user", role}); got != c.admin {
			t.Errorf("HoldsAdmin(user, %q) = %v, want %v", role, got, c.admin)
		}
	}
}
