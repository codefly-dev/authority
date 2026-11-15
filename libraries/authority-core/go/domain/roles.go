package domain

import (
	"maps"
	"slices"
)

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
//   - the crossover: when a declaration of exactly admin and user replaces
//     one whose grants hold the old names, those grants move to the new
//     names instead of ending (CrossoverRole, applied where undeclared grants
//     are dropped; Crossovers, listed among what an update asks), so nobody
//     loses access. A viewer's holders gain whatever user holds: the owner's
//     decision for this one release (2026-11-15). Each move is journaled
//     with Detail CrossoverFrom, so an audit tells it from a deliberate grant.
//
// TODO(next release): delete LegacyInstallerRole, legacyRoles, CrossoverRole,
// Crossovers, CrossoverFrom and the alias in IsAdminRole and
// DeclaredAdminRole; roles_test.go and the
// legacy_installer tests pin both, so removal is deliberate.
const LegacyInstallerRole = "installer"

// legacyRoles maps each old person role to the one that succeeds it: the
// installer's grants become admin's, the editor's and the viewer's user's.
// STOPGAP: see LegacyInstallerRole.
var legacyRoles = map[string]string{LegacyInstallerRole: AdminRole, "editor": UserRole, "viewer": UserRole}

// CrossoverFrom is the journal Detail key naming the old role a grant moved
// from (CrossoverRole). STOPGAP: see LegacyInstallerRole.
const CrossoverFrom = "crossover_from"

// CrossoverRole is the role a grant of role moves to when declared, the next
// declaration's roles, no longer declares role: its successor (legacyRoles),
// and only when declared is exactly admin and user, the page-role rename. A
// target that declares a custom role beside them, and later drops one named
// like an old role, ends its grants as any dropped role's. False for any other
// role, and for a role declared still. STOPGAP: see LegacyInstallerRole.
func CrossoverRole[V any](role string, declared map[string]V) (string, bool) {
	_, admin := declared[AdminRole]
	_, user := declared[UserRole]
	if len(declared) != 2 || !admin || !user {
		return "", false
	}
	next, ok := legacyRoles[role]
	return next, ok
}

// Crossovers lists, in a review's words, the old roles approved declares
// whose holders move when next replaces it (CrossoverRole): what an update
// asks beyond its declaration. STOPGAP: see LegacyInstallerRole.
func Crossovers[V any](approved, next map[string]V) []string {
	var out []string
	for _, old := range slices.Sorted(maps.Keys(approved)) {
		if role, ok := CrossoverRole(old, next); ok {
			out = append(out, "holders of role "+old+" move to "+role)
		}
	}
	return out
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
