package authority

import (
	"context"
	"errors"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// Store is where a host keeps the authority's state. Read runs fn over one
// consistent snapshot. Write runs fn as one transaction: all of fn's writes
// or none, so an fn that fails leaves nothing behind. An adapter that meets a
// serialization conflict retries fn (it must be free of other effects) and,
// when it gives up, reports an error wrapping ErrConflict. A missing record
// is reported wrapping domain.ErrNotFound.
type Store interface {
	Read(ctx context.Context, fn func(Tx) error) error
	Write(ctx context.Context, fn func(Tx) error) error
}

// ErrConflict is what a Store reports when a transaction could not commit
// against a concurrent one and was not retried to success.
var ErrConflict = errors.New("authority: the transaction conflicted with another")

// Tx is one transaction's view. Identity (organizations, people, teams and
// organization roles) is the host's: the authority only reads it.
type Tx interface {
	Organizations() ([]domain.Organization, error)
	Organization(id string) (domain.Organization, error)
	// Person answers whether id names a person at all, in any organization.
	// A person may belong to several organizations, so the authority reads
	// nothing else from it: what a person holds is read through Member.
	Person(id string) (domain.Person, error)
	// Member is a person as a member of one organization: their roles and
	// teams there. A person who is not a member of it is ErrNotFound.
	Member(organization, id string) (domain.Person, error)
	People(organization string) ([]domain.Person, error)
	// TeamExists reads the host's current team directory in this transaction,
	// independently of membership. Empty teams exist; absent, deleted and
	// other-organization teams answer false. Storage failures return an error.
	TeamExists(organization, id string) (bool, error)
	OrgRole(organization, name string) (domain.OrgRole, error)

	// Module answers by principal, ModuleNamed by name; Modules lists every one.
	Module(principal string) (domain.Module, error)
	ModuleNamed(name string) (domain.Module, error)
	Modules() ([]domain.Module, error)
	PutModule(domain.Module) error
	DeleteModule(name string) error
	// Tombstone answers what stays of a withdrawn module, by name, and
	// TombstoneByPrincipal by its principal. A tombstone is never removed.
	Tombstone(name string) (domain.Tombstone, error)
	TombstoneByPrincipal(principal string) (domain.Tombstone, error)
	PutTombstone(domain.Tombstone) error
	// ApprovedModule answers the declaration of module name at generation, as
	// it stood when an installation's consent approved it; PutApprovedModule
	// keeps one, keyed by name and generation: rewriting the same declaration
	// is accepted, a different one at a kept (name, generation) is refused
	// with domain.ErrApprovedDeclarationKept and changes nothing. The core writes
	// it whenever a consent is taken or advances (Install, an upgrade, a
	// re-convergence), and reads it to decide what the holders of an
	// installation whose consent is behind the delivered generation hold:
	// the approved roles, never the delivered ones. A host's store must keep
	// every generation an active installation's consent names; it may drop
	// one no consent names any more.
	ApprovedModule(name string, generation uint64) (domain.Module, error)
	PutApprovedModule(domain.Module) error

	Installation(id string) (domain.Installation, error)
	InstallationByPrincipal(principal string) (domain.Installation, error)
	// Installations lists an organization's, or every one when it is "".
	Installations(organization string) ([]domain.Installation, error)
	PutInstallation(domain.Installation) error

	RoleGrants(installationID string) ([]domain.RoleGrant, error)
	PutRoleGrant(domain.RoleGrant) error          // idempotent
	DeleteRoleGrant(domain.RoleGrant) error       // idempotent
	DeleteRoleGrants(installationID string) error // an uninstall clears them

	// AuthorizationRevision is an organization's, from 1; a bump invalidates
	// every capability minted at it.
	AuthorizationRevision(organization string) (uint64, error)
	BumpAuthorizationRevision(organization string) error
	// PersonEpoch moves when a person leaves a team or the organization.
	PersonEpoch(person string) (uint64, error)
	BumpPersonEpoch(person string) error
	// GrantEpoch moves when a person loses a role on one installation.
	GrantEpoch(person, installationID string) (uint64, error)
	BumpGrantEpoch(person, installationID string) error
	// OwnerAwareRevision moves when an audience withdraws owner-aware checking.
	OwnerAwareRevision(audience string) (uint64, error)
	BumpOwnerAwareRevision(audience string) error

	Delegation(id string) (domain.Delegation, error)
	Delegations() ([]domain.Delegation, error)
	PutDelegation(domain.Delegation) error
	Client(id string) (domain.Client, error)
	PutClient(domain.Client) error

	// RoleView answers the role view a session was opened with, ErrNotFound
	// when it has none. PutRoleView records one; the core writes a session's
	// view once and never changes it.
	RoleView(sessionID string) (domain.RoleView, error)
	PutRoleView(domain.RoleView) error
}
