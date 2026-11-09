package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

// RBAC-4a: a module that adopts owner checks narrows what was issued at it.
// Rob's own-session capability at the ledger, issued while it checked no
// owner, no longer checks once the ledger checks owners, and a fresh issue is
// refused by name.
func TestAModuleAdoptingOwnerChecksEndsOwnSessionCapabilities(t *testing.T) {
	h := newHarness(t)
	before := h.must(h.root("rob", "ledger"))
	if err := h.check(before); err != nil {
		t.Fatal(err)
	}
	aware := ledger()
	aware.Generation, aware.OwnerAware = 2, true
	if _, err := h.svc.ApplyModule(h.ctx, aware); err != nil {
		t.Fatal(err)
	}
	if err := h.check(before); err == nil {
		t.Fatal("a capability issued before the ledger checked owners still checks")
	}
	if _, err := h.svc.ListResources(h.ctx, before.Token, "ledger", ledgerKind, "read"); err == nil {
		t.Fatal("a capability issued before the ledger checked owners still lists")
	}
	_, err := h.root("rob", "ledger")
	refused(t, err, "ledger checks owners, so an organization role reaches none of its owned data on a person's own session")
}

// A kind the store no longer shares narrows too: Rob's own-session capability
// on it ends, and a fresh issue is refused by name.
func TestAKindNoLongerSharedEndsOwnSessionCapabilities(t *testing.T) {
	h := newHarness(t)
	shared := storeAt(2, "admin", true)
	shared.SharedKinds = []string{kind}
	if _, err := h.svc.ApplyModule(h.ctx, shared); err != nil {
		t.Fatal(err)
	}
	before := h.must(h.root("rob", "store"))
	if err := h.check(before); err != nil {
		t.Fatal(err)
	}
	unshared := storeAt(3, "admin", true)
	if _, err := h.svc.ApplyModule(h.ctx, unshared); err != nil {
		t.Fatal(err)
	}
	if err := h.check(before); err == nil {
		t.Fatal("a capability on a kind no longer shared still checks")
	}
	_, err := h.root("rob", "store")
	refused(t, err, "store checks owners, so an organization role reaches none of its owned data")
}

// A capability minted before owner checks applied, with no revision moved
// since (a code rollout over a module already checking owners), still checks,
// and ListResources answers none of the owned kind from organization roles.
func TestListResourcesAnswersNoOwnedKindFromOrganizationRoles(t *testing.T) {
	h := newHarness(t)
	before := h.must(h.root("rob", "ledger"))
	aware := ledger()
	aware.OwnerAware = true
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutModule(aware) }); err != nil {
		t.Fatal(err)
	}
	if err := h.check(before); err != nil {
		t.Fatalf("the test needs the old capability to still check: %v", err)
	}
	grants, err := h.svc.ListResources(h.ctx, before.Token, "ledger", ledgerKind, "read")
	if err != nil || len(grants) != 0 {
		t.Fatalf("listed %v (%v) of an owned kind from organization roles", grants, err)
	}
}
