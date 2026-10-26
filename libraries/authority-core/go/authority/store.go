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
	Person(id string) (domain.Person, error)
	People(organization string) ([]domain.Person, error)
	OrgRole(organization, name string) (domain.OrgRole, error)

	// Module answers by principal, ModuleNamed by name; Modules lists every one.
	Module(principal string) (domain.Module, error)
	ModuleNamed(name string) (domain.Module, error)
	Modules() ([]domain.Module, error)
	PutModule(domain.Module) error
	DeleteModule(name string) error

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
}
