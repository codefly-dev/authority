package memstore

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// The store keeps access grants beside the authority's state, under the one
// lock and in the one transaction: a Write that uninstalls an installation
// can forget its grants in the same commit (access.Journal), and a failed
// transaction undoes both.
var (
	_ access.Store = (*Store)(nil)
	_ access.Tx    = tx{}
)

// ReadAccess runs fn over one snapshot of the grants, under the read lock.
func (s *Store) ReadAccess(_ context.Context, fn func(access.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fn(tx{s: s})
}

// WriteAccess runs fn as one transaction, as Write does.
func (s *Store) WriteAccess(_ context.Context, fn func(access.Tx) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, committed := s.snapshot(), false
	defer func() {
		if !committed {
			s.restore(before)
		}
	}()
	if err = fn(tx{s: s, write: true}); err != nil {
		return err
	}
	committed = true
	s.sequence++
	return nil
}

func cloneGrant(g domain.AccessGrant) domain.AccessGrant {
	g.Actions = slices.Clone(g.Actions)
	g.Sources = slices.Clone(g.Sources)
	return g
}

func (t tx) AccessGrant(key domain.AccessKey) (domain.AccessGrant, error) {
	g, ok := t.s.access[key]
	if !ok {
		return g, missing("access grant", key.Kind+"/"+key.ResourceID)
	}
	return cloneGrant(g), nil
}

func (t tx) PutAccessGrant(g domain.AccessGrant) error {
	t.mustWrite()
	t.s.access[g.AccessKey] = cloneGrant(g)
	t.s.accessRevisions[g.Organization]++
	return nil
}

func (t tx) DeleteAccessGrant(key domain.AccessKey) (bool, error) {
	t.mustWrite()
	if _, ok := t.s.access[key]; !ok {
		return false, nil
	}
	delete(t.s.access, key)
	t.s.accessRevisions[key.Organization]++
	return true, nil
}

func (t tx) AccessGrantsOn(organization string, refs []access.Ref, now time.Time) ([]domain.AccessGrant, error) {
	return t.accessGrants(now, func(g domain.AccessGrant) bool {
		return g.Organization == organization && slices.Contains(refs, access.Ref{Kind: g.Kind, ResourceID: g.ResourceID})
	}), nil
}

func (t tx) AccessGrantsTo(organization string, subjects []domain.AccessSubject, now time.Time) ([]domain.AccessGrant, error) {
	return t.accessGrants(now, func(g domain.AccessGrant) bool {
		return g.Organization == organization && slices.Contains(subjects, g.Subject)
	}), nil
}

func (t tx) DeleteAccessGrantsTo(organization string, subject domain.AccessSubject) (int, error) {
	t.mustWrite()
	n := 0
	for key := range t.s.access {
		if key.Organization == organization && key.Subject == subject {
			delete(t.s.access, key)
			n++
		}
	}
	if n > 0 {
		t.s.accessRevisions[organization]++
	}
	return n, nil
}

// AccessRevision is from 1, as the authorization revision is.
func (t tx) AccessRevision(organization string) (uint64, error) {
	return t.s.accessRevisions[organization] + 1, nil
}

// AccessSequence is the store's count of committed transactions and identity
// changes, from 1, in this process's epoch: one order for every organization,
// which is a valid order for each and moves more often than one needs. A write
// transaction answers the count it commits at.
func (t tx) AccessSequence(string) (access.Sequence, error) {
	at := access.Sequence{Epoch: t.s.epoch, Value: t.s.sequence + 1}
	if t.write {
		at.Value++
	}
	return at, nil
}

// accessGrants are the grants keep admits that are live at now (every one
// when now is zero), ordered by kind, id, version and subject.
func (t tx) accessGrants(now time.Time, keep func(domain.AccessGrant) bool) []domain.AccessGrant {
	var out []domain.AccessGrant
	for _, g := range t.s.access {
		if keep(g) && (now.IsZero() || g.Live(now)) {
			out = append(out, cloneGrant(g))
		}
	}
	slices.SortFunc(out, func(a, b domain.AccessGrant) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.ResourceID, b.ResourceID), cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Subject.Kind, b.Subject.Kind), cmp.Compare(a.Subject.ID, b.Subject.ID))
	})
	return out
}
