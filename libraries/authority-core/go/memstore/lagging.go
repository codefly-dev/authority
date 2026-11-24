package memstore

import (
	"context"
	"maps"
	"sync"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
)

// Lagged is a reader of a store's access grants that can fall behind it, as a
// replica does: what a host's tests put before access.Service, with the store
// itself as access.Config.Primary, to prove a decision is never read from a
// state earlier than the minimum asked. Until Freeze it reads the store.
type Lagged struct {
	primary *Store
	mu      sync.RWMutex
	frozen  *Store
}

var _ access.Store = (*Lagged)(nil)

// Lagging is a reader of s that reads s itself until it is frozen.
func Lagging(s *Store) *Lagged { return &Lagged{primary: s} }

// Freeze holds the reader at the store's state now: every ReadAccess answers
// that state, its sequence included, whatever is written after, until CatchUp.
func (l *Lagged) Freeze() {
	l.primary.mu.RLock()
	frozen := &Store{access: maps.Clone(l.primary.access), accessRevisions: maps.Clone(l.primary.accessRevisions),
		sequence: l.primary.sequence, epoch: l.primary.epoch}
	l.primary.mu.RUnlock()
	l.mu.Lock()
	l.frozen = frozen
	l.mu.Unlock()
}

// CatchUp lets the reader read the store again.
func (l *Lagged) CatchUp() {
	l.mu.Lock()
	l.frozen = nil
	l.mu.Unlock()
}

// ReadAccess reads the frozen state, or the store's when none is held.
func (l *Lagged) ReadAccess(ctx context.Context, fn func(access.Tx) error) error {
	l.mu.RLock()
	frozen := l.frozen
	l.mu.RUnlock()
	if frozen != nil {
		return frozen.ReadAccess(ctx, fn)
	}
	return l.primary.ReadAccess(ctx, fn)
}

// WriteAccess writes the store: a lagging reader takes no write.
func (l *Lagged) WriteAccess(ctx context.Context, fn func(access.Tx) error) error {
	return l.primary.WriteAccess(ctx, fn)
}
