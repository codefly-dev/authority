package access

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// Sequence is one point in a host's order of access-relevant changes for an
// organization: every change that can alter a decision there (a grant, a role,
// a team, a membership, an installation) moves Value, in commit order, and
// never back. Epoch names one unbroken history of that order: it changes only
// when the history is discarded (a restart of an in-memory host, a restore to
// an earlier point), and sequences of two epochs are not comparable.
type Sequence struct {
	Epoch [16]byte
	Value uint64
}

// Revision is the state of one organization a host answered at. A module
// stores and returns it as Opaque gives it and never reads it.
type Revision struct {
	Organization string
	Sequence
}

// revisionV1 is the one encoding: the version byte, the epoch and the
// sequence as an unsigned varint. Both hosts encode it here.
const revisionV1 = 0x01

// Opaque is the revision as the wire carries it.
func (r Revision) Opaque() []byte {
	out := append(make([]byte, 0, 27), revisionV1)
	out = append(out, r.Epoch[:]...)
	return binary.AppendUvarint(out, r.Value)
}

// Minimum is a revision a caller names as the earliest state an answer may be
// computed at, as the wire carries it. The zero Minimum names none.
type Minimum struct {
	Organization string
	Opaque       []byte
}

// Set is whether the caller named a revision at all: any field set.
func (m Minimum) Set() bool { return m.Organization != "" || len(m.Opaque) > 0 }

// The reasons a revision is refused by, and the reason no state at or past a
// minimum could be reached, as the wire carries them.
const (
	RevisionForeign = "revision_foreign"
	RevisionUnknown = "revision_unknown"
)

// ErrUnavailable is answered when the host cannot reach a state at or past
// the minimum asked: the store read lags it and the store holding the newest
// state does not answer. A transport reports it UNAVAILABLE with the reason
// StaleRevision; no decision is ever read from the earlier state instead.
var ErrUnavailable = errors.New(StaleRevision + ": no state at or past the minimum asked can be reached")

// lagStep is how often a lagging store is read again within Config.LagWait.
const lagStep = 25 * time.Millisecond

// DefaultLagWait is how long a read waits for a lagging store to reach the
// minimum asked before it reads Config.Primary.
const DefaultLagWait = 100 * time.Millisecond

// minimums holds the minimums of one request to what this host serves and
// answers the ones set, parsed. A host that serves none refuses any set one,
// and a request for the newest state, as a precondition it does not honour:
// it never ignores either. A revision of another organization is refused
// RevisionForeign, the same whether that organization exists; bytes this host
// does not encode are refused RevisionUnknown.
func (s *Service) minimums(org string, mins ...Minimum) ([]Sequence, error) {
	var out []Sequence
	for _, m := range mins {
		if !m.Set() {
			continue
		}
		if m.Organization != org {
			return nil, domain.Malformed(RevisionForeign)
		}
		raw := m.Opaque
		if len(raw) < 18 || raw[0] != revisionV1 {
			return nil, domain.NotNow(RevisionUnknown)
		}
		var seq Sequence
		copy(seq.Epoch[:], raw[1:17])
		value, n := binary.Uvarint(raw[17:])
		if n <= 0 || n != len(raw)-17 {
			return nil, domain.NotNow(RevisionUnknown)
		}
		seq.Value = value
		out = append(out, seq)
	}
	return out, nil
}

// served refuses a request that names a minimum or asks for the newest state
// when this host serves neither.
func (s *Service) served(head bool, mins ...Minimum) error {
	if s.cfg.MinRevisions {
		return nil
	}
	set := head
	for _, m := range mins {
		set = set || m.Set()
	}
	if set {
		return domain.NotNow("this host honours no revision precondition yet; ask without min_revision and freshness")
	}
	return nil
}

// writer is the store changes are written to: the one holding the newest state.
func (s *Service) writer() Store {
	if s.cfg.Primary != nil {
		return s.cfg.Primary
	}
	return s.store
}

// view runs fn over one snapshot of organization's grants that is at or past
// every minimum, and answers the revision of that snapshot. head reads the
// newest committed state. A store behind a minimum never decides: it is read
// again for Config.LagWait, then the primary is; a primary that does not
// answer is ErrUnavailable. A minimum of another epoch, or past the newest
// state, was never issued by this history and is refused RevisionUnknown.
func (s *Service) view(ctx context.Context, org string, head bool, mins []Sequence, fn func(Tx) error) (Revision, error) {
	var floor uint64
	for _, m := range mins {
		floor = max(floor, m.Value)
	}
	read := func(store Store) (at Sequence, behind, stored bool, err error) {
		err = store.ReadAccess(ctx, func(tx Tx) error {
			stored = true
			var err error
			if at, err = tx.AccessSequence(org); err != nil {
				return err
			}
			for _, m := range mins {
				if m.Epoch != at.Epoch {
					return domain.NotNow(RevisionUnknown)
				}
			}
			if behind = at.Value < floor; behind {
				return nil
			}
			return fn(tx)
		})
		return at, behind, stored, err
	}
	primary := s.cfg.Primary
	if primary != nil && !head {
		wait := s.cfg.LagWait
		if wait == 0 {
			wait = DefaultLagWait
		}
		for deadline := time.Now().Add(wait); ; {
			at, behind, _, err := read(s.store)
			if err != nil {
				return Revision{}, err
			}
			if !behind {
				return Revision{Organization: org, Sequence: at}, nil
			}
			if !time.Now().Add(lagStep).Before(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return Revision{}, ctx.Err()
			case <-time.After(lagStep):
			}
		}
	}
	store := s.store
	if primary != nil {
		store = primary
	}
	at, behind, stored, err := read(store)
	switch {
	case err != nil && !stored && primary != nil:
		// The store holding the newest state did not answer at all.
		return Revision{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	case err != nil:
		return Revision{}, err
	case behind:
		return Revision{}, domain.NotNow(RevisionUnknown)
	}
	return Revision{Organization: org, Sequence: at}, nil
}
