package authority_test

import (
	"testing"
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
	if grants, err := h.svc.ListResources(h.ctx, before.Token, "ledger", ledgerKind, "read"); err == nil && len(grants) > 0 {
		t.Fatalf("a capability issued before the ledger checked owners still lists %v", grants)
	}
	_, err := h.root("rob", "ledger")
	refused(t, err, "ledger checks owners, so an organization role reaches none of its owned data on a person's own session")
}
