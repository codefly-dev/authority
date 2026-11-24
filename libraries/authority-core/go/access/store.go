package access

import (
	"context"
	"errors"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// Store is where a host keeps access grants. It is separate from
// authority.Store on purpose: a host that implements authority.Tx keeps
// building when this interface arrives, and adopts it when it serves the
// access interface. ReadAccess runs fn over one consistent snapshot of the
// grants, their revision and the sequence; WriteAccess runs fn as one
// transaction, all of its writes or none. A store that could not open the
// snapshot at all answers an error without calling fn. A missing grant is reported wrapping domain.ErrNotFound.
type Store interface {
	ReadAccess(ctx context.Context, fn func(Tx) error) error
	WriteAccess(ctx context.Context, fn func(Tx) error) error
}

// Ref names a resource whatever its version: what grants are listed on.
type Ref struct {
	Kind, ResourceID string
}

// Tx is one transaction's view of the grants.
type Tx interface {
	// AccessGrant answers the grant at key, expired or not; ErrNotFound when
	// there is none.
	AccessGrant(key domain.AccessKey) (domain.AccessGrant, error)
	// PutAccessGrant writes g at its natural key, replacing the grant there.
	PutAccessGrant(g domain.AccessGrant) error
	// DeleteAccessGrant removes the grant at key and reports whether there
	// was one: deleting nothing is no error and says so.
	DeleteAccessGrant(key domain.AccessKey) (existed bool, err error)
	// AccessGrantsOn lists organization's grants on any of refs, every
	// version of each, that are live at now; a zero now lists expired ones
	// too. Ordered by kind, id, version and subject.
	AccessGrantsOn(organization string, refs []Ref, now time.Time) ([]domain.AccessGrant, error)
	// AccessGrantsTo lists organization's grants held by any of subjects that
	// are live at now; a zero now lists expired ones too. Same order.
	AccessGrantsTo(organization string, subjects []domain.AccessSubject, now time.Time) ([]domain.AccessGrant, error)
	// DeleteAccessGrantsTo removes every grant of organization held by
	// subject and answers how many there were.
	DeleteAccessGrantsTo(organization string, subject domain.AccessSubject) (int, error)
	// AccessRevision names the state of organization's grants: it moves on
	// every put and on every delete that removed one, and never goes back. A
	// ListViewerGrants page token binds it.
	AccessRevision(organization string) (uint64, error)
	// AccessSequence is the point of organization's order of access-relevant
	// changes this transaction reads at: in ReadAccess the snapshot's, in
	// WriteAccess the one the transaction commits at, so a later read at or
	// past it sees the transaction's writes. A host that keeps no such order
	// yet answers a zero epoch and AccessRevision's value, and leaves
	// Config.MinRevisions false.
	AccessSequence(organization string) (Sequence, error)
}

// ForgetInstallation ends every grant made to an installation, for good: the
// host calls it in the transaction that uninstalls. A reinstall keeps the
// installation's id and principal, so a grant left standing would be held
// again by the next incarnation; none is.
func ForgetInstallation(tx Tx, organization, installationID string) (int, error) {
	return tx.DeleteAccessGrantsTo(organization, domain.AccessSubject{Kind: domain.AccessInstallation, ID: installationID})
}

// Journal wraps a host's authority journal (authority.Config.Journal) so an
// uninstall forgets the installation's access grants in the transaction that
// uninstalls it. It is for a host whose authority transaction also carries
// the access grants (the in-memory store's does); such a transaction that
// does not is an error, so the uninstall fails rather than leaving a grant a
// reinstall would revive. A host with its own stores deletes in its own
// uninstall transaction instead (ForgetInstallation). next may be nil.
func Journal(next func(context.Context, authority.Tx, domain.Event) error) func(context.Context, authority.Tx, domain.Event) error {
	return func(ctx context.Context, tx authority.Tx, e domain.Event) error {
		if e.Kind == domain.InstallationUninstalled {
			grants, ok := tx.(Tx)
			if !ok {
				return errors.New("access: the authority transaction carries no access grants, so an uninstall cannot forget them")
			}
			if _, err := ForgetInstallation(grants, e.Organization, e.Subject); err != nil {
				return err
			}
		}
		if next == nil {
			return nil
		}
		return next(ctx, tx, e)
	}
}
