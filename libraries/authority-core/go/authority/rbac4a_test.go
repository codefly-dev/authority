package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

// RBAC-4a: a module that adopts owner checks narrows what was issued at it.
// Maya's capability at the ledger through the page's binding, issued
// unselected while the ledger checked no owner, no longer checks once it
// does, and a fresh one selects the page installation's data.
func TestAModuleAdoptingOwnerChecksEndsUnselectedCapabilities(t *testing.T) {
	h := newHarness(t)
	ledgerPage(t, h)
	h.grant("pages", "user", "maya")
	before := h.must(h.page("maya", "pages", "ledger"))
	exactly(t, before, ledgerKind, "", []string{"read"})
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
	exactly(t, h.must(h.page("maya", "pages", "ledger")), ledgerKind, h.principal(acme, "pages"), []string{"read"})
	// On a person's own session the ledger holds nothing, before or after.
	_, err := h.root("maya", "ledger")
	refused(t, err, "ledger declares no roles")
}

// A kind the store no longer shares narrows too: maya's unselected capability
// on it through the page's binding ends, and a fresh one selects the page
// installation's data.
func TestAKindNoLongerSharedEndsUnselectedCapabilities(t *testing.T) {
	h := newHarness(t)
	shared := storeAt(2, "admin", true)
	shared.SharedKinds = []string{kind}
	if _, err := h.svc.ApplyModule(h.ctx, shared); err != nil {
		t.Fatal(err)
	}
	ledgerPage(t, h)
	h.grant("pages", "user", "maya")
	before := h.must(h.page("maya", "pages", "store"))
	exactly(t, before, kind, "", []string{"read"})
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
	exactly(t, h.must(h.page("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
}

// A capability minted unselected before owner checks applied, with no
// revision moved since (a code rollout over a module already checking
// owners), still checks, and ListResources answers the kind as the roles
// reach it now: the page installation's data and no unowned resource.
func TestListResourcesAnswersAnOwnedKindAsTheInstallationsDataAlone(t *testing.T) {
	h := newHarness(t)
	ledgerPage(t, h)
	h.grant("pages", "user", "maya")
	before := h.must(h.page("maya", "pages", "ledger"))
	aware := ledger()
	aware.OwnerAware = true
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutModule(aware) }); err != nil {
		t.Fatal(err)
	}
	if err := h.check(before); err != nil {
		t.Fatalf("the test needs the old capability to still check: %v", err)
	}
	grants, err := h.svc.ListResources(h.ctx, before.Token, "ledger", ledgerKind, "read")
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		if g.Owner != h.principal(acme, "pages") {
			t.Fatalf("listed %+v of an owned kind beyond the page installation's data", g)
		}
	}
}
