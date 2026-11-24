package storetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/google/uuid"
)

// OpenAccess opens a host's access.Store.
type OpenAccess func(t *testing.T) access.Store

// RunAccess proves the contract every access.Store must meet, against the
// in-memory store here and each host's own there: a grant reads back as
// written and replaces the one at its natural key, a delete says whether
// there was a grant, grants are listed by reference and by subject set in one
// order, a listing at an instant leaves out what expired, the revision moves
// with every change and never goes back, organizations share nothing, and a
// failed transaction leaves nothing behind. Every id is fresh, so a host may
// run it against a store other tests share.
func RunAccess(t *testing.T, open OpenAccess) {
	t.Helper()
	ctx := context.Background()
	store := open(t)
	org, other := "org-"+uuid.NewString(), "org-"+uuid.NewString()
	kind, collection := "kind-"+uuid.NewString(), "collection-"+uuid.NewString()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	person := domain.AccessSubject{Kind: domain.AccessPerson, ID: "person-" + uuid.NewString()}
	team := domain.AccessSubject{Kind: domain.AccessTeam, ID: "team-" + uuid.NewString()}
	installation := domain.AccessSubject{Kind: domain.AccessInstallation, ID: "installation-" + uuid.NewString()}
	grant := func(o, k, id, version string, subject domain.AccessSubject, actions ...string) domain.AccessGrant {
		return domain.AccessGrant{ID: uuid.NewString(), AccessKey: domain.AccessKey{Organization: o, Kind: k, ResourceID: id, Version: version, Subject: subject},
			Actions: actions, GrantedBy: "granter", CreatedAt: now}
	}
	read := func(t *testing.T, fn func(access.Tx) error) {
		t.Helper()
		if err := store.ReadAccess(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	write := func(t *testing.T, fn func(access.Tx) error) {
		t.Helper()
		if err := store.WriteAccess(ctx, fn); err != nil {
			t.Fatal(err)
		}
	}
	revision := func(t *testing.T, o string) uint64 {
		t.Helper()
		var rev uint64
		read(t, func(tx access.Tx) (err error) { rev, err = tx.AccessRevision(o); return err })
		return rev
	}
	keys := func(grants []domain.AccessGrant) []domain.AccessKey {
		out := make([]domain.AccessKey, len(grants))
		for i, g := range grants {
			out[i] = g.AccessKey
		}
		return out
	}

	t.Run("a grant reads back as written; a missing one is ErrNotFound", func(t *testing.T) {
		g := grant(org, kind, "read-back", "v1", person, "read", "write")
		g.ExpiresAt = now.Add(time.Hour)
		read(t, func(tx access.Tx) error {
			if _, err := tx.AccessGrant(g.AccessKey); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("a missing grant answers %v, want ErrNotFound", err)
			}
			return nil
		})
		write(t, func(tx access.Tx) error { return tx.PutAccessGrant(g) })
		read(t, func(tx access.Tx) error {
			got, err := tx.AccessGrant(g.AccessKey)
			if err != nil {
				return err
			}
			if got.ID != g.ID || got.AccessKey != g.AccessKey || !slices.Equal(got.Actions, g.Actions) || !got.ExpiresAt.Equal(g.ExpiresAt) || got.GrantedBy != g.GrantedBy || !got.CreatedAt.Equal(g.CreatedAt) {
				t.Errorf("read back %+v, want %+v", got, g)
			}
			// The version is part of the key: the unpinned grant is another.
			unpinned := g.AccessKey
			unpinned.Version = ""
			if _, err := tx.AccessGrant(unpinned); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("the grant following versions answers %v beside a pinned one", err)
			}
			return nil
		})
	})
	t.Run("a put at the same natural key replaces the grant; one grant stands", func(t *testing.T) {
		first := grant(org, kind, "replaced", "", person, "read")
		second := first
		second.Actions, second.ExpiresAt, second.GrantedBy = []string{"read", "share"}, now.Add(time.Hour), "another"
		write(t, func(tx access.Tx) error { return tx.PutAccessGrant(first) })
		write(t, func(tx access.Tx) error { return tx.PutAccessGrant(second) })
		read(t, func(tx access.Tx) error {
			listed, err := tx.AccessGrantsOn(org, []access.Ref{{Kind: kind, ResourceID: "replaced"}}, time.Time{})
			if err != nil {
				return err
			}
			if len(listed) != 1 || !slices.Equal(listed[0].Actions, second.Actions) || listed[0].GrantedBy != "another" || !listed[0].ExpiresAt.Equal(second.ExpiresAt) {
				t.Errorf("after a replace the reference holds %+v", listed)
			}
			return nil
		})
	})
	t.Run("a delete reports whether a grant existed", func(t *testing.T) {
		g := grant(org, kind, "deleted", "", person, "read")
		write(t, func(tx access.Tx) error {
			if existed, err := tx.DeleteAccessGrant(g.AccessKey); err != nil || existed {
				t.Errorf("deleting nothing answered existed=%t, %v", existed, err)
			}
			return tx.PutAccessGrant(g)
		})
		write(t, func(tx access.Tx) error {
			if existed, err := tx.DeleteAccessGrant(g.AccessKey); err != nil || !existed {
				t.Errorf("deleting a grant answered existed=%t, %v", existed, err)
			}
			if existed, err := tx.DeleteAccessGrant(g.AccessKey); err != nil || existed {
				t.Errorf("deleting it twice answered existed=%t, %v", existed, err)
			}
			return nil
		})
		read(t, func(tx access.Tx) error {
			if _, err := tx.AccessGrant(g.AccessKey); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("a deleted grant answers %v", err)
			}
			return nil
		})
	})
	t.Run("grants are listed by reference, every version, and by subject set, in one order; an instant leaves out what expired; organizations share nothing", func(t *testing.T) {
		expired := grant(org, kind, "listed-a", "v2", person, "read")
		expired.ExpiresAt = now
		lasting := grant(org, kind, "listed-a", "v1", person, "read")
		lasting.ExpiresAt = now.Add(time.Second)
		all := []domain.AccessGrant{
			grant(org, kind, "listed-b", "", team, "read"),
			grant(org, kind, "listed-a", "", team, "read"),
			grant(org, kind, "listed-a", "", person, "read"),
			lasting, expired,
			grant(org, collection, "listed-c", "", installation, "read"),
			grant(other, kind, "listed-a", "", person, "read"),
		}
		write(t, func(tx access.Tx) error {
			for _, g := range all {
				if err := tx.PutAccessGrant(g); err != nil {
					return err
				}
			}
			return nil
		})
		a := func(version string, s domain.AccessSubject) domain.AccessKey {
			return domain.AccessKey{Organization: org, Kind: kind, ResourceID: "listed-a", Version: version, Subject: s}
		}
		read(t, func(tx access.Tx) error {
			on, err := tx.AccessGrantsOn(org, []access.Ref{{Kind: kind, ResourceID: "listed-a"}, {Kind: collection, ResourceID: "listed-c"}}, now)
			if err != nil {
				return err
			}
			// Ordered by kind, id, version, subject kind, subject id.
			want := []domain.AccessKey{a("", person), a("", team), a("v1", person),
				{Organization: org, Kind: collection, ResourceID: "listed-c", Subject: installation}}
			slices.SortStableFunc(want, func(x, y domain.AccessKey) int {
				if x.Kind != y.Kind {
					if x.Kind < y.Kind {
						return -1
					}
					return 1
				}
				return 0
			})
			if !slices.Equal(keys(on), want) {
				t.Errorf("listed on the references %v, want %v", keys(on), want)
			}
			every, err := tx.AccessGrantsOn(org, []access.Ref{{Kind: kind, ResourceID: "listed-a"}}, time.Time{})
			if err != nil {
				return err
			}
			if want := []domain.AccessKey{a("", person), a("", team), a("v1", person), a("v2", person)}; !slices.Equal(keys(every), want) {
				t.Errorf("listed with no instant %v, want %v", keys(every), want)
			}
			to, err := tx.AccessGrantsTo(org, []domain.AccessSubject{person, installation}, now)
			if err != nil {
				return err
			}
			for _, g := range to {
				if g.Organization != org || (g.Subject != person && g.Subject != installation) || !g.Live(now) {
					t.Errorf("listed to the subjects: %+v", g)
				}
			}
			var listed int
			for _, g := range to {
				if g.ResourceID == "listed-a" || g.ResourceID == "listed-c" {
					listed++
				}
			}
			if listed != 3 {
				t.Errorf("listed %d of the three live grants the subjects hold on the fixture's references: %v", listed, keys(to))
			}
			if none, err := tx.AccessGrantsTo(org, nil, now); err != nil || len(none) != 0 {
				t.Errorf("no subject lists %v, %v", none, err)
			}
			after, err := tx.AccessGrantsOn(org, []access.Ref{{Kind: kind, ResourceID: "listed-a"}}, now.Add(time.Second))
			if err != nil {
				return err
			}
			if want := []domain.AccessKey{a("", person), a("", team)}; !slices.Equal(keys(after), want) {
				t.Errorf("listed once the pinned grant expired %v, want %v", keys(after), want)
			}
			return nil
		})
	})
	t.Run("every grant of one subject is deleted at once, and counted; another organization's and another subject's stand", func(t *testing.T) {
		subject := domain.AccessSubject{Kind: domain.AccessInstallation, ID: "installation-" + uuid.NewString()}
		write(t, func(tx access.Tx) error {
			for _, g := range []domain.AccessGrant{grant(org, kind, "forgotten-a", "", subject, "read"), grant(org, kind, "forgotten-b", "v1", subject, "read"),
				grant(other, kind, "forgotten-a", "", subject, "read"), grant(org, kind, "forgotten-a", "", team, "read")} {
				if err := tx.PutAccessGrant(g); err != nil {
					return err
				}
			}
			return nil
		})
		write(t, func(tx access.Tx) error {
			if n, err := access.ForgetInstallation(tx, org, subject.ID); err != nil || n != 2 {
				t.Errorf("forgot %d grants, %v; want 2", n, err)
			}
			if n, err := access.ForgetInstallation(tx, org, subject.ID); err != nil || n != 0 {
				t.Errorf("forgot %d grants the second time, %v", n, err)
			}
			return nil
		})
		read(t, func(tx access.Tx) error {
			if left, err := tx.AccessGrantsTo(org, []domain.AccessSubject{subject}, time.Time{}); err != nil || len(left) != 0 {
				t.Errorf("the subject still holds %v, %v", left, err)
			}
			if kept, err := tx.AccessGrantsTo(other, []domain.AccessSubject{subject}, time.Time{}); err != nil || len(kept) != 1 {
				t.Errorf("another organization's grant: %v, %v", kept, err)
			}
			if kept, err := tx.AccessGrantsOn(org, []access.Ref{{Kind: kind, ResourceID: "forgotten-a"}}, time.Time{}); err != nil || len(kept) != 1 || kept[0].Subject != team {
				t.Errorf("another subject's grant: %v, %v", kept, err)
			}
			return nil
		})
	})
	t.Run("the revision moves with every put and every delete that removed a grant, never back, one organization at a time", func(t *testing.T) {
		g := grant(org, kind, "revised", "", person, "read")
		start, elsewhere := revision(t, org), revision(t, other)
		write(t, func(tx access.Tx) error { return tx.PutAccessGrant(g) })
		put := revision(t, org)
		write(t, func(tx access.Tx) error { return tx.PutAccessGrant(g) })
		again := revision(t, org)
		write(t, func(tx access.Tx) error { _, err := tx.DeleteAccessGrant(g.AccessKey); return err })
		deleted := revision(t, org)
		write(t, func(tx access.Tx) error { _, err := tx.DeleteAccessGrant(g.AccessKey); return err })
		if !(start < put && put < again && again < deleted) {
			t.Errorf("revisions %d, %d, %d, %d do not grow with each change", start, put, again, deleted)
		}
		if nothing := revision(t, org); nothing != deleted {
			t.Errorf("deleting nothing moved the revision from %d to %d", deleted, nothing)
		}
		if revision(t, other) != elsewhere {
			t.Errorf("another organization's revision moved")
		}
	})
	t.Run("a failed transaction leaves nothing behind", func(t *testing.T) {
		kept := grant(org, kind, "atomic-kept", "", person, "read")
		lost := grant(org, kind, "atomic-lost", "", person, "read")
		write(t, func(tx access.Tx) error { return tx.PutAccessGrant(kept) })
		before := revision(t, org)
		failed := errors.New("the transaction fails")
		err := store.WriteAccess(ctx, func(tx access.Tx) error {
			if err := tx.PutAccessGrant(lost); err != nil {
				return err
			}
			if _, err := tx.DeleteAccessGrant(kept.AccessKey); err != nil {
				return err
			}
			return failed
		})
		if !errors.Is(err, failed) {
			t.Fatalf("the transaction answered %v", err)
		}
		read(t, func(tx access.Tx) error {
			if _, err := tx.AccessGrant(lost.AccessKey); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("a failed transaction's put stands: %v", err)
			}
			if _, err := tx.AccessGrant(kept.AccessKey); err != nil {
				t.Errorf("a failed transaction's delete stands: %v", err)
			}
			return nil
		})
		if after := revision(t, org); after != before {
			t.Errorf("a failed transaction moved the revision from %d to %d", before, after)
		}
	})
}

// RunAccessSequence proves what a store must meet before its host serves
// revision minimums (access.Config.MinRevisions): one epoch, a sequence that
// moves with every committed change and never back, and a write transaction
// that answers the sequence it commits at, so a read at or past it sees the
// write. A host that serves no minimum yet does not run it.
func RunAccessSequence(t *testing.T, open OpenAccess) {
	t.Helper()
	ctx := context.Background()
	store := open(t)
	org := "org-" + uuid.NewString()
	subject := domain.AccessSubject{Kind: domain.AccessPerson, ID: "person-" + uuid.NewString()}
	at := func() access.Sequence {
		t.Helper()
		var seq access.Sequence
		if err := store.ReadAccess(ctx, func(tx access.Tx) (err error) { seq, err = tx.AccessSequence(org); return err }); err != nil {
			t.Fatal(err)
		}
		return seq
	}
	before := at()
	if before.Epoch == [16]byte{} {
		t.Fatal("a store that orders its changes names the epoch of that order")
	}
	last := before
	for i, change := range []func(access.Tx) error{
		func(tx access.Tx) error {
			return tx.PutAccessGrant(domain.AccessGrant{ID: uuid.NewString(), AccessKey: domain.AccessKey{Organization: org, Kind: "kind", ResourceID: "id", Subject: subject}, Actions: []string{"read"}})
		},
		func(tx access.Tx) error {
			_, err := tx.DeleteAccessGrant(domain.AccessKey{Organization: org, Kind: "kind", ResourceID: "id", Subject: subject})
			return err
		},
	} {
		var committed access.Sequence
		if err := store.WriteAccess(ctx, func(tx access.Tx) (err error) {
			if err = change(tx); err != nil {
				return err
			}
			committed, err = tx.AccessSequence(org)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		after := at()
		if committed.Epoch != before.Epoch || after.Epoch != before.Epoch {
			t.Fatalf("change %d moved the epoch", i)
		}
		if committed.Value <= last.Value || after.Value < committed.Value {
			t.Fatalf("change %d: read at %d before it, committed at %d, read at %d after it", i, last.Value, committed.Value, after.Value)
		}
		last = after
	}
}
