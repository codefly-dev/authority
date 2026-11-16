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
//     HoldsAdmin, DeclaredAdminRole). No other old role name (editor, viewer,
//     steward) is an alias of anything, and a declaration naming both "installer" and
//     "admin" is refused (decide.ValidateModule), so no target holds two
//     admin-powered roles;
//   - the crossover: when a declaration of exactly admin and user replaces
//     one whose grants hold the old names, those grants move instead of
//     ending, by a fixed rule (CrossoverRole, applied where undeclared grants
//     are dropped; Crossovers, listed among what an update asks): installer
//     to admin, every other old role (editor, viewer, steward) to user. They
//     move at the approval of an administrator's consent, and with the
//     delivery, or the host's next replay of a generation it holds already,
//     for an installation no consent holds or one composition's receipt
//     holds when the update asks nothing beyond the rename. This
//     is the owner's least-privilege decision (2026-11-15): a page's user
//     holds only what the page's screens call, so a former editor or steward
//     may hold less than before, and an admin promotes whoever needs more;
//     nobody is promoted to admin by the rename. Each move is journaled with
//     Detail CrossoverFrom and CrossoverBasis, so an audit tells it from a
//     deliberate grant.
//
// TODO(next release): delete LegacyInstallerRole, CrossoverRole, Crossovers,
// CrossoverFrom, CrossoverBasis and its values, Renamed, the alias in IsAdminRole
// and DeclaredAdminRole, and the core's crossesOnly and its replay pass
// (reconverge's strandedOnly); roles_test.go and the legacy_installer tests pin
// both, so removal is deliberate.
const LegacyInstallerRole = "installer"

// CrossoverFrom is the journal Detail key naming the old role a grant moved
// from (CrossoverRole). STOPGAP: see LegacyInstallerRole.
const CrossoverFrom = "crossover_from"

// CrossoverBasis is the journal Detail key saying which rule moved a grant,
// one of the basis values below. STOPGAP: see LegacyInstallerRole.
const CrossoverBasis = "crossover_basis"

// The basis of a move (CrossoverRole). STOPGAP: see LegacyInstallerRole.
const (
	// BasisInstaller: installer moves to admin.
	BasisInstaller = "installer"
	// BasisLegacyToUser: editor, viewer and steward move to user.
	BasisLegacyToUser = "legacy_to_user"
)

// CrossoverRole is the role a grant of old moves to, and the basis of the
// move, when next, the next declaration's roles, is exactly admin and user
// (the page-role rename): installer to admin, whose powers its holder
// already has through the alias; editor, viewer and steward (the old
// directory's role defining record types) to user, whatever they held
// (least privilege: an admin promotes whoever needs more). False for any
// other role name, and for next not exactly admin and user: a target that
// keeps a custom role beside them and drops one named like an old role ends
// its grants as any dropped role's. STOPGAP: see LegacyInstallerRole.
func CrossoverRole[V any](old string, next map[string]V) (role, basis string, ok bool) {
	if !Renamed(next) {
		return "", "", false
	}
	switch old {
	case LegacyInstallerRole:
		return AdminRole, BasisInstaller, true
	case "editor", "viewer", "steward":
		return UserRole, BasisLegacyToUser, true
	}
	return "", "", false
}

// Renamed reports whether roles are exactly admin and user: the
// declaration the page-role rename crosses old grants over to
// (CrossoverRole). STOPGAP: see LegacyInstallerRole.
func Renamed[V any](roles map[string]V) bool {
	_, admin := roles[AdminRole]
	_, user := roles[UserRole]
	return len(roles) == 2 && admin && user
}

// Crossovers lists, in a review's words, the old roles approved declares
// whose holders move when next replaces it (CrossoverRole): what an update
// asks beyond its declaration. STOPGAP: see LegacyInstallerRole.
func Crossovers[V any](approved, next map[string]V) []string {
	var out []string
	for _, old := range slices.Sorted(maps.Keys(approved)) {
		if role, _, ok := CrossoverRole(old, next); ok {
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
