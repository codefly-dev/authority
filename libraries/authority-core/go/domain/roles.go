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
// STOPGAP, one release only. Everything below that names it, and
// CrossoverRole, is the stopgap, deleted together:
//
//   - the alias: a host is published after the modules on a deployment, so a
//     delivery stored before the rename, or an incoming one not yet
//     re-rendered, still names "installer". Until every delivery has crossed,
//     a declaration of "installer" satisfies the admin requirement and a
//     holder of it administers as an admin holder does (IsAdminRole,
//     HoldsAdmin, DeclaredAdminRole). No other old role name (editor, viewer)
//     is an alias of anything, and a declaration naming both "installer" and
//     "admin" is refused (decide.ValidateModule), so no target holds two
//     admin-powered roles;
//   - the crossover: when a declaration naming admin and user replaces one
//     whose grants hold the old names, those grants move to the new names
//     instead of ending (CrossoverRole, applied where undeclared grants are
//     dropped), so nobody loses access.
//
// TODO(next release): delete LegacyInstallerRole, legacyRoles, CrossoverRole
// and the alias in IsAdminRole and DeclaredAdminRole; roles_test.go and the
// legacy_installer tests pin both, so removal is deliberate.
const LegacyInstallerRole = "installer"

// legacyRoles maps each old person role to the one that succeeds it: the
// installer's grants become admin's, the editor's and the viewer's user's.
// STOPGAP: see LegacyInstallerRole.
var legacyRoles = map[string]string{LegacyInstallerRole: AdminRole, "editor": UserRole, "viewer": UserRole}

// CrossoverRole is the role a grant of role moves to when declared, the next
// declaration's roles, no longer declares role: its successor (legacyRoles),
// when declared declares that. False for any other role, for a role declared
// still, and when the successor is not declared. STOPGAP: see
// LegacyInstallerRole.
func CrossoverRole[V any](role string, declared map[string]V) (string, bool) {
	if _, still := declared[role]; still {
		return "", false
	}
	next, ok := legacyRoles[role]
	if !ok {
		return "", false
	}
	if _, ok := declared[next]; !ok {
		return "", false
	}
	return next, true
}

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
