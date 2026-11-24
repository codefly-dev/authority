package access

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// A share made on by a grantee never outlives the power it was made from.
// Such a grant records the grants that gave its grantor share on the
// reference (domain.AccessGrant.Sources), and it stands for an action only
// while one of them
//   - is still the grant it was: at its key, under the same id (a grant
//     revoked and made again is another grant, so restoring a share revives
//     nothing that rested on the one revoked);
//   - is still its grantor's: made to them, to a team they still belong to,
//     or to their installation while it is installed;
//   - still covers the reference where it sits now (a share made on from a
//     collection's grant ends when the document leaves the collection);
//   - itself stands, for share and for the action, by the same rule.
//
// The rule is evaluated when a decision is made, never by deleting: a revoke,
// an expiry, a narrowed re-grant, a team left or an uninstall anywhere up the
// chain ends every share made on below it at the state that change is part
// of, with nothing more to write, so a decision asked at the change's
// revision already sees it.

// lineage is what the rule reads: the grants of one snapshot with their
// sources, transitively, and whose grants count for each grantor now.
type lineage struct {
	grants   map[domain.AccessKey]domain.AccessGrant
	subjects map[string][]domain.AccessSubject
	now      time.Time
}

// maxLineage bounds the grants one question follows sources through.
const maxLineage = 4096

// sourcesOf reads, in tx, grants and every grant they rest on, transitively,
// by key. A source that is gone is absent.
func sourcesOf(tx Tx, grants []domain.AccessGrant) (map[domain.AccessKey]domain.AccessGrant, error) {
	out := map[domain.AccessKey]domain.AccessGrant{}
	queue := slices.Clone(grants)
	for len(queue) > 0 {
		g := queue[0]
		queue = queue[1:]
		if _, seen := out[g.AccessKey]; seen {
			continue
		}
		if len(out) == maxLineage {
			return nil, domain.NotNow("the shares this question rests on are more than %d", maxLineage)
		}
		out[g.AccessKey] = g
		for _, src := range g.Sources {
			if _, seen := out[src.Key]; seen {
				continue
			}
			s, err := tx.AccessGrant(src.Key)
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			queue = append(queue, s)
		}
	}
	return out, nil
}

// lineageOf resolves, outside any store transaction, whose grants count for
// the grantor of every grant that rests on another.
func (s *Service) lineageOf(ctx context.Context, org string, grants map[domain.AccessKey]domain.AccessGrant, now time.Time) (lineage, error) {
	l := lineage{grants: grants, subjects: map[string][]domain.AccessSubject{}, now: now}
	for _, g := range grants {
		if len(g.Sources) == 0 {
			continue
		}
		if _, done := l.subjects[g.GrantedBy]; done {
			continue
		}
		subjects, err := s.authority.AccessSubjectsOf(ctx, org, g.GrantedBy)
		if err != nil {
			return lineage{}, err
		}
		l.subjects[g.GrantedBy] = subjects
	}
	return l, nil
}

// gives is whether g stands for action: live, giving it, and, when it rests
// on other grants, by one that still stands. p is where the question's
// resource sits; nil, for a listing that places nothing, a source on a
// collection is taken to cover still.
func (l lineage) gives(g domain.AccessGrant, action string, p *Placement) bool {
	return l.stands(g, action, p, map[domain.AccessKey]bool{})
}

// givesAny is whether g stands for any action it gives.
func (l lineage) givesAny(g domain.AccessGrant, p *Placement) bool {
	return slices.ContainsFunc(g.Actions, func(a string) bool { return l.gives(g, a, p) })
}

func (l lineage) stands(g domain.AccessGrant, action string, p *Placement, following map[domain.AccessKey]bool) bool {
	if !g.Live(l.now) || !g.Gives(action) {
		return false
	}
	if len(g.Sources) == 0 {
		return true
	}
	if following[g.AccessKey] {
		return false
	}
	following[g.AccessKey] = true
	defer delete(following, g.AccessKey)
	for _, src := range g.Sources {
		s, ok := l.grants[src.Key]
		if !ok || s.ID != src.ID || !slices.Contains(l.subjects[g.GrantedBy], s.Subject) || !reaches(s, g, p) {
			continue
		}
		if l.stands(s, ShareAction, p, following) && (action == ShareAction || l.stands(s, action, p, following)) {
			return true
		}
	}
	return false
}

// reaches is whether source still covers the reference g is on: the same
// resource, following its versions or at g's version, or a collection the
// placement still names above.
func reaches(source, g domain.AccessGrant, p *Placement) bool {
	if source.Kind == g.Kind && source.ResourceID == g.ResourceID {
		return source.Version == "" || source.Version == g.Version
	}
	if p == nil {
		return true
	}
	return slices.ContainsFunc(p.Ancestors, func(a Node) bool {
		return source.Kind == a.Kind && source.ResourceID == a.ResourceID && (source.Version == "" || source.Version == a.Version)
	})
}

// errMoved is a write that found other grants than the ones its lineage was
// resolved for: it is tried again.
var errMoved = errors.New("access: the grants changed while they were being resolved")

// managing runs fn as one write transaction over the live grants on refs and
// their lineage. Whose grants count for a grantor is read from the authority,
// which no store transaction may hold open, so the grants are read first, the
// lineage resolved, and the write made only if it finds the same grants; when
// it does not, the whole is tried again, and a reference written to that
// often is answered ErrStale.
func (s *Service) managing(ctx context.Context, org string, refs []Ref, now time.Time, fn func(tx Tx, grants []domain.AccessGrant, l lineage) error) error {
	read := func(tx Tx) ([]domain.AccessGrant, map[domain.AccessKey]domain.AccessGrant, error) {
		grants, err := tx.AccessGrantsOn(org, refs, now)
		if err != nil {
			return nil, nil, err
		}
		all, err := sourcesOf(tx, grants)
		return grants, all, err
	}
	for range 4 {
		var seen map[domain.AccessKey]domain.AccessGrant
		if err := s.writer().ReadAccess(ctx, func(tx Tx) (err error) {
			_, seen, err = read(tx)
			return err
		}); err != nil {
			return err
		}
		l, err := s.lineageOf(ctx, org, seen, now)
		if err != nil {
			return err
		}
		err = s.writer().WriteAccess(ctx, func(tx Tx) error {
			grants, all, err := read(tx)
			if err != nil {
				return err
			}
			if !sameGrants(all, seen) {
				return errMoved
			}
			return fn(tx, grants, l)
		})
		if !errors.Is(err, errMoved) {
			return err
		}
	}
	return ErrStale
}

// sameGrants is whether two reads found the same grants, as the rule reads
// them.
func sameGrants(a, b map[domain.AccessKey]domain.AccessGrant) bool {
	if len(a) != len(b) {
		return false
	}
	for key, x := range a {
		y, ok := b[key]
		if !ok || x.ID != y.ID || x.GrantedBy != y.GrantedBy || !x.ExpiresAt.Equal(y.ExpiresAt) ||
			!slices.Equal(x.Actions, y.Actions) || !slices.Equal(x.Sources, y.Sources) {
			return false
		}
	}
	return true
}
