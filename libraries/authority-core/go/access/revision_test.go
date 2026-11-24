package access_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
)

// down is a primary that does not answer: it never opens a snapshot.
type down struct{ access.Store }

func (down) ReadAccess(context.Context, func(access.Tx) error) error {
	return errors.New("connection refused")
}

// lagging rebuilds the world's service as a host that serves minimums over a
// reader that can fall behind its store.
func (w *world) lagging(primary func(*memstore.Store) access.Store) *memstore.Lagged {
	w.t.Helper()
	lag := memstore.Lagging(w.store)
	var head access.Store = w.store
	if primary != nil {
		head = primary(w.store)
	}
	svc, err := access.New(w.auth, lag, access.Config{Clock: func() time.Time { return w.now }, MinRevisions: true, Primary: head, LagWait: time.Millisecond})
	if err != nil {
		w.t.Fatal(err)
	}
	w.svc = svc
	return lag
}

func min(r access.Revision) access.Minimum {
	return access.Minimum{Organization: r.Organization, Opaque: r.Opaque()}
}

func (w *world) grantAt(token string, p access.Placement, subject domain.AccessSubject) access.Revision {
	w.t.Helper()
	_, rev, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: token, Actor: serving, Subject: subject, Actions: []string{"read"}, Placement: p,
		Target: access.Target{Kind: p.Resource.Kind, ResourceID: p.Resource.ResourceID, Version: p.Resource.Version}})
	if err != nil {
		w.t.Fatal(err)
	}
	return rev
}

func (w *world) revokeAt(token string, p access.Placement, subject domain.AccessSubject) access.Revision {
	w.t.Helper()
	_, rev, err := w.svc.Revoke(w.ctx, access.RevokeRequest{Token: token, Actor: serving, Subject: subject, Placement: p,
		Target: access.Target{Kind: p.Resource.Kind, ResourceID: p.Resource.ResourceID, Version: p.Resource.Version}})
	if err != nil {
		w.t.Fatal(err)
	}
	return rev
}

func (w *world) checkAt(token string, p access.Placement, head bool, mins ...access.Revision) (access.Decision, access.Revision, error) {
	r := access.CheckRequest{Token: token, Actor: serving, Action: "read", Placements: []access.Placement{p}, Head: head}
	if len(mins) > 0 {
		r.MinRevision = min(mins[0])
	}
	out, rev, err := w.svc.Check(w.ctx, r)
	if err != nil {
		return access.Decision{}, rev, err
	}
	return out[0], rev, nil
}

func TestEveryChangeAnswersALaterRevisionOfOneEpochAndADecisionDominatesItsMinimum(t *testing.T) {
	w := newWorld(t)
	w.lagging(nil)
	da := w.doc("da", "dana")
	granted := w.grantAt(w.as("dana", "a"), da, person("carol"))
	_, read, err := w.checkAt(w.as("carol", "a"), da, false, granted)
	if err != nil {
		t.Fatal(err)
	}
	revoked := w.revokeAt(w.as("dana", "a"), da, person("carol"))
	if granted.Organization != acme || granted.Epoch != revoked.Epoch || granted.Epoch == [16]byte{} || revoked.Value <= granted.Value || read.Value < granted.Value {
		t.Fatalf("granted at %+v, read at %+v, revoked at %+v", granted, read, revoked)
	}
	if len(granted.Opaque()) > 27 {
		t.Fatalf("a revision is %d bytes", len(granted.Opaque()))
	}
	// Any change that can alter a decision moves the order, not grants alone.
	w.store.PutPerson(domain.Person{ID: "tom", Organization: acme})
	_, after, err := w.checkAt(w.as("carol", "a"), da, true)
	if err != nil || after.Value <= revoked.Value {
		t.Fatalf("after a membership change the newest state is %+v, %v; the revoke was %+v", after, err, revoked)
	}
}

func TestADecisionAskedWithAMinimumIsNeverReadFromAnEarlierState(t *testing.T) {
	w := newWorld(t)
	lag := w.lagging(nil)
	da := w.doc("da", "dana")
	w.grantAt(w.as("dana", "a"), da, person("carol"))
	lag.Freeze()
	revoked := w.revokeAt(w.as("dana", "a"), da, person("carol"))
	// Without a minimum the lagging reader answers what it holds: the hazard.
	stale, at, err := w.checkAt(w.as("carol", "a"), da, false)
	if err != nil || !stale.Allowed || at.Value >= revoked.Value {
		t.Fatalf("the frozen reader answered %+v at %+v, %v", stale, at, err)
	}
	// The publisher asks the newest state and records it; the revoked reader
	// asked with that minimum is denied while the reader is still behind.
	_, head, err := w.checkAt(w.as("dana", "a"), da, true)
	if err != nil || head.Value < revoked.Value {
		t.Fatalf("the newest state is %+v, %v; the revoke was %+v", head, err, revoked)
	}
	for _, minimum := range []access.Revision{revoked, head} {
		got, at, err := w.checkAt(w.as("carol", "a"), da, false, minimum)
		if err != nil || got.Allowed || at.Value < minimum.Value {
			t.Fatalf("asked at %+v: %+v at %+v, %v", minimum, got, at, err)
		}
	}
	if still, _, _ := w.checkAt(w.as("carol", "a"), da, false); !still.Allowed {
		t.Fatal("the reader caught up by itself: the case proved nothing")
	}
	// A grant is read back by its own revision under the same lag.
	db := w.doc("db", "dana")
	granted := w.grantAt(w.as("dana", "a"), db, person("carol"))
	if got, _, err := w.checkAt(w.as("carol", "a"), db, false, granted); err != nil || !got.Allowed {
		t.Fatalf("a grant asked at its own revision: %+v, %v", got, err)
	}
	// The viewer's grants asked with the minimum leave the revoked one out.
	page, err := w.svc.ListViewerGrants(w.ctx, access.ViewerGrantsRequest{Token: w.as("carol", "a"), Actor: serving, Kinds: []string{docKind}, Action: "read", MinRevision: min(granted)})
	if err != nil || len(page.Resources) != 1 || page.Resources[0].ResourceID != "db" || page.Revision.Value < granted.Value {
		t.Fatalf("the viewer's grants are %+v, %v", page, err)
	}
	// A batch is one state at or past the latest of its minimums.
	out, at, err := w.svc.Check(w.ctx, access.CheckRequest{Token: w.as("carol", "a"), Actor: serving, Action: "read", Placements: []access.Placement{da, db},
		ItemMinRevisions: []access.Minimum{{}, min(granted)}})
	if err != nil || out[0].Allowed || !out[1].Allowed || at.Value < granted.Value {
		t.Fatalf("the batch answered %+v at %+v, %v", out, at, err)
	}
	_, _, err = w.svc.Check(w.ctx, access.CheckRequest{Token: w.as("carol", "a"), Actor: serving, Action: "read", Placements: []access.Placement{da, db},
		ItemMinRevisions: []access.Minimum{min(granted)}})
	refusal(t, err, domain.Invalid, "for every placement or for none")
	lag.CatchUp()
	if got, _, err := w.checkAt(w.as("carol", "a"), da, false); err != nil || got.Allowed {
		t.Fatalf("caught up, the reader answers %+v, %v", got, err)
	}
}

func TestAGrantExpiresByTheClockWhateverRevisionIsAsked(t *testing.T) {
	w := newWorld(t)
	lag := w.lagging(nil)
	da := w.doc("da", "dana")
	_, granted, err := w.svc.Grant(w.ctx, access.GrantRequest{Token: w.as("dana", "a"), Actor: serving, Subject: person("carol"), Actions: []string{"read"}, Placement: da,
		Target: access.Target{Kind: docKind, ResourceID: "da"}, ExpiresAt: w.now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	lag.Freeze()
	w.now = w.now.Add(2 * time.Minute)
	if got, _, err := w.checkAt(w.as("carol", "a"), da, false, granted); err != nil || got.Allowed {
		t.Fatalf("past its expiry the grant answers %+v, %v", got, err)
	}
}

func TestARevisionThisHistoryNeverIssuedIsRefused(t *testing.T) {
	w := newWorld(t)
	w.lagging(nil)
	da := w.doc("da", "dana")
	granted := w.grantAt(w.as("dana", "a"), da, person("carol"))
	ask := func(m access.Minimum) error {
		_, _, err := w.svc.Check(w.ctx, access.CheckRequest{Token: w.as("carol", "a"), Actor: serving, Action: "read", Placements: []access.Placement{da}, MinRevision: m})
		return err
	}
	// Another organization's, the same whether it exists.
	for _, org := range []string{globex, "no-such-organization", ""} {
		err := ask(access.Minimum{Organization: org, Opaque: granted.Opaque()})
		refusal(t, err, domain.Invalid, access.RevisionForeign)
		if err.Error() != access.RevisionForeign {
			t.Fatalf("the refusal %q names more than its reason", err)
		}
	}
	ahead, elsewhere := granted, granted
	ahead.Value += 1 << 20
	elsewhere.Epoch[3] ^= 0xff
	version := granted.Opaque()
	version[0] = 0x02
	for name, opaque := range map[string][]byte{
		"past the newest state": ahead.Opaque(), "another epoch": elsewhere.Opaque(), "an unknown encoding": version,
		"nothing": nil, "truncated": granted.Opaque()[:17], "trailing bytes": append(granted.Opaque(), 0),
		"an unterminated sequence": append(bytes.Clone(granted.Opaque()[:17]), 0x80),
	} {
		t.Run(name, func(t *testing.T) {
			refusal(t, ask(access.Minimum{Organization: acme, Opaque: opaque}), domain.Precondition, access.RevisionUnknown)
		})
	}
	if err := ask(min(granted)); err != nil {
		t.Fatalf("the revision as issued: %v", err)
	}
}

func TestWhenTheNewestStateDoesNotAnswerNoDecisionIsMade(t *testing.T) {
	w := newWorld(t)
	da := w.doc("da", "dana")
	w.lagging(nil)
	w.grantAt(w.as("dana", "a"), da, person("carol"))
	revoked := w.revokeAt(w.as("dana", "a"), da, person("carol"))
	// The same store behind a reader frozen at the revoke, its primary down.
	lag := w.lagging(func(*memstore.Store) access.Store { return down{} })
	lag.Freeze()
	later := revoked
	later.Value += 2
	// The reader is at the revoke: a minimum it holds is served without the primary.
	if got, _, err := w.checkAt(w.as("carol", "a"), da, false, revoked); err != nil || got.Allowed {
		t.Fatalf("a minimum the reader holds: %+v, %v", got, err)
	}
	for name, ask := range map[string]func() error{
		"a minimum the reader has not reached": func() error { _, _, err := w.checkAt(w.as("carol", "a"), da, false, later); return err },
		"the newest state":                     func() error { _, _, err := w.checkAt(w.as("carol", "a"), da, true); return err },
	} {
		if err := ask(); !errors.Is(err, access.ErrUnavailable) {
			t.Fatalf("%s: want ErrUnavailable, got %v", name, err)
		}
	}
}

// Many rounds of revoke, publish and read, the reader frozen before the
// revoke in every other one: once a revoke has returned and the publisher has
// asked the newest state, no reader asking with the publisher's revision is
// allowed, however many ask at once.
func TestNoReaderIsAllowedAtAPublishersRevisionAfterTheRevokeBeforeIt(t *testing.T) {
	w := newWorld(t)
	lag := w.lagging(nil)
	da := w.doc("da", "dana")
	dana, carol := w.as("dana", "a"), w.as("carol", "a")
	for round := range 20 {
		w.grantAt(dana, da, person("carol"))
		if round%2 == 0 {
			lag.Freeze()
		}
		w.revokeAt(dana, da, person("carol"))
		_, head, err := w.checkAt(dana, da, true)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, at, err := w.checkAt(carol, da, false, head)
				if err != nil || got.Allowed || at.Value < head.Value {
					t.Errorf("round %d: a reader at the publisher's revision %+v answered %+v at %+v, %v", round, head, got, at, err)
				}
			}()
		}
		wg.Wait()
		lag.CatchUp()
	}
}
