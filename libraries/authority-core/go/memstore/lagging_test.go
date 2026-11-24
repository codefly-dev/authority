package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/access"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
)

func TestALaggingReaderServesTheStateAtFreezeUntilCatchUp(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	lag := memstore.Lagging(store)
	key := func(id string) domain.AccessKey {
		return domain.AccessKey{Organization: "acme", Kind: "documents", ResourceID: id, Subject: domain.AccessSubject{Kind: domain.AccessPerson, ID: "carol"}}
	}
	put := func(id string) {
		t.Helper()
		// Written through the reader: a lagging reader takes no write, the store does.
		if err := lag.WriteAccess(ctx, func(tx access.Tx) error {
			return tx.PutAccessGrant(domain.AccessGrant{ID: id, AccessKey: key(id), Actions: []string{"read"}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(s access.Store, id string) (held bool, at access.Sequence) {
		t.Helper()
		if err := s.ReadAccess(ctx, func(tx access.Tx) (err error) {
			if at, err = tx.AccessSequence("acme"); err != nil {
				return err
			}
			_, err = tx.AccessGrant(key(id))
			held = err == nil
			if errors.Is(err, domain.ErrNotFound) {
				err = nil
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return held, at
	}
	put("before")
	if held, _ := read(lag, "before"); !held {
		t.Fatal("until it is frozen the reader reads the store")
	}
	lag.Freeze()
	_, frozen := read(lag, "before")
	put("after")
	if err := store.WriteAccess(ctx, func(tx access.Tx) error {
		_, err := tx.DeleteAccessGrant(key("before"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	before, at := read(lag, "before")
	after, _ := read(lag, "after")
	if !before || after || at != frozen {
		t.Fatalf("frozen, the reader holds before=%v after=%v at %d; want the state at %d", before, after, at.Value, frozen.Value)
	}
	if _, head := read(store, "after"); head.Epoch != frozen.Epoch || head.Value <= frozen.Value {
		t.Fatalf("the store is at %d of the reader's epoch=%v; want past %d", head.Value, head.Epoch == frozen.Epoch, frozen.Value)
	}
	lag.CatchUp()
	before, at = read(lag, "before")
	after, _ = read(lag, "after")
	if before || !after || at.Value <= frozen.Value {
		t.Fatalf("caught up, the reader holds before=%v after=%v at %d", before, after, at.Value)
	}
}
