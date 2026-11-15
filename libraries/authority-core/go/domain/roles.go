package domain

import (
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
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
//     HoldsAdmin, DeclaredAdminRole). No other old role name (editor, viewer,
//     steward) is an alias of anything, and a declaration naming both "installer" and
//     "admin" is refused (decide.ValidateModule), so no target holds two
//     admin-powered roles;
//   - the crossover: when a declaration of exactly admin and user replaces
//     one whose grants hold the old names, those grants move instead of
//     ending, each to the narrowest new role that covers what the old role
//     held (CrossoverRole, applied where undeclared grants are dropped;
//     Crossovers, listed among what an update asks), so nobody loses access:
//     each holder lands on a role that holds at least what their old one
//     declared, unless the target's own admin declares less than an old role
//     did (its choice, which the update's review names). The one exception
//     beyond that is an editor, viewer or steward of an installation whose
//     approved declaration the store does not keep (a legacy consent
//     recording no generation): nothing proves what covers it, so it ends as
//     before, journaled. A holder may gain: a viewer moved to user holds whatever user declares,
//     the owner's decision for this one release (2026-11-15). Each move is
//     journaled with Detail CrossoverFrom, so an audit tells it from a
//     deliberate grant.
//
// TODO(next release): delete LegacyInstallerRole, CrossoverRole, Crossovers,
// CrossoverFrom and the alias in IsAdminRole and DeclaredAdminRole; roles_test.go and the
// legacy_installer tests pin both, so removal is deliberate.
const LegacyInstallerRole = "installer"

// CrossoverFrom is the journal Detail key naming the old role a grant moved
// from (CrossoverRole). STOPGAP: see LegacyInstallerRole.
const CrossoverFrom = "crossover_from"

// CrossoverRole is the role a grant of old moves to when next, the next
// declaration's roles, replaces approved, the declaration the grant was held
// under, and next is exactly admin and user (the page-role rename):
//
//   - installer always moves to admin, whose powers its holder already has
//     through the alias;
//   - editor, viewer and steward (the old directory's role defining record
//     types) move to the narrowest new role whose declared scopes cover what
//     old declared in approved: user when user's scopes cover them
//     (scope.Attenuates), otherwise admin. An editor who wrote what the new
//     user only reads keeps writing, and a steward who defined what user
//     cannot keeps defining, as admin. Admin holds every action the target
//     serves when its roles are derived; a declaration of admin narrower than
//     an old role is the target's own choice, which its review shows
//     (Crossovers).
//
// False for any other role name; for next not exactly admin and user (a
// target that keeps a custom role beside them and drops one named like an old
// role ends its grants as any dropped role's); and for editor, viewer or
// steward when approved does not declare old, since what it held is unknown. STOPGAP: see
// LegacyInstallerRole.
func CrossoverRole(old string, approved, next map[string][]*basev0.WorkScopeV1) (string, bool) {
	_, admin := next[AdminRole]
	user, hasUser := next[UserRole]
	if len(next) != 2 || !admin || !hasUser {
		return "", false
	}
	switch old {
	case LegacyInstallerRole:
		return AdminRole, true
	case "editor", "viewer", "steward":
		held, ok := approved[old]
		if !ok {
			return "", false
		}
		if scope.Attenuates(held, user) {
			return UserRole, true
		}
		return AdminRole, true
	}
	return "", false
}

// Crossovers lists, in a review's words, the old roles approved declares
// whose holders move when next replaces it (CrossoverRole): what an update
// asks beyond its declaration. STOPGAP: see LegacyInstallerRole.
func Crossovers(approved, next map[string][]*basev0.WorkScopeV1) []string {
	var out []string
	for _, old := range slices.Sorted(maps.Keys(approved)) {
		if role, ok := CrossoverRole(old, approved, next); ok {
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
