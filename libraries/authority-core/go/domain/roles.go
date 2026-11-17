package domain

import "slices"

// The two roles a person holds on a solution or a module page, and the only
// two: no other name is declared, granted or held (IsRole). Admin is the one
// the authority gives meaning: a solution, or a module page declaring roles,
// declares it; its holder administers the installation's role grants and
// approves a module page's pending update. User is the standard role beside
// it, reading and writing the target's own kinds; it carries no meaning here
// beyond the scopes it declares.
const (
	AdminRole = "admin"
	UserRole  = "user"
)

// IsRole reports whether name is one of the two roles, admin or user. No
// former name of either ("installer", "editor", "viewer", "steward") is one:
// a delivery declaring any other name is refused by it (decide.PageRoles),
// nobody is granted one (decide.ChangeRole), and a grant of one a store
// still holds is held as nothing (decide.HeldRoles).
func IsRole(name string) bool { return name == AdminRole || name == UserRole }

// IsAdminRole reports whether role is the admin role.
func IsAdminRole(role string) bool { return role == AdminRole }

// HoldsAdmin reports whether roles, the roles a person holds on one
// installation, include the admin role.
func HoldsAdmin(roles []string) bool { return slices.Contains(roles, AdminRole) }
