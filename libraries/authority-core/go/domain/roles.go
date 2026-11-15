package domain

import "slices"

// The two person roles of a module page or a solution. Admin is the one the
// authority gives meaning: a solution, or a module page declaring roles,
// declares it; its holder administers the installation's role grants and
// approves a module page's pending update. User is the standard role beside
// it, reading and writing the target's own kinds; it carries no meaning here
// beyond the scopes it declares.
const (
	AdminRole = "admin"
	UserRole  = "user"
)

// LegacyInstallerRole is the admin role's name before it was renamed.
//
// STOPGAP, one release only: a host is published after the modules on a
// deployment, so a delivery stored before the rename, or an incoming one not
// yet re-rendered, still names "installer". Until every delivery has crossed,
// a declaration of "installer" satisfies the admin requirement and a holder
// of it administers as an admin holder does. No other old role name (editor,
// viewer) is an alias of anything.
//
// TODO(next release): delete LegacyInstallerRole and the alias in
// IsAdminRole and DeclaredAdminRole; roles_test.go pins the alias so that
// removal is deliberate.
const LegacyInstallerRole = "installer"

// IsAdminRole reports whether role is the admin role, or, for one release,
// its legacy name (LegacyInstallerRole).
func IsAdminRole(role string) bool {
	return role == AdminRole || role == LegacyInstallerRole
}

// HoldsAdmin reports whether roles, the roles a person holds on one
// installation, include the admin role (IsAdminRole).
func HoldsAdmin(roles []string) bool { return slices.ContainsFunc(roles, IsAdminRole) }

// DeclaredAdminRole is the name under which roles, a target's declared
// roles, declare the admin role: AdminRole when declared, else, for one
// release, LegacyInstallerRole when declared; false when neither is.
func DeclaredAdminRole[V any](roles map[string]V) (string, bool) {
	if _, ok := roles[AdminRole]; ok {
		return AdminRole, true
	}
	if _, ok := roles[LegacyInstallerRole]; ok {
		return LegacyInstallerRole, true
	}
	return "", false
}
