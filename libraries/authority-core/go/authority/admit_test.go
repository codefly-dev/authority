package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// pageNamingBeyondReach is the page at generation reaching the store as
// pageReachingStore(generation, "read") does, with a second binding to the
// legacy store, which carries read alone, and its viewer naming write of the
// legacy kind through it: a reach the composition does not hold, which the
// core refuses by name (decide.Unreached).
func pageNamingBeyondReach(generation uint64) domain.Module {
	m := pageReachingStore(generation, "read")
	m.Bindings["legacy"] = domain.Binding{ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}
	m.Roles["viewer"] = append(m.Roles["viewer"], sc(legacyKind, "write"))
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"viewer": {"legacy": {sc(legacyKind, "write")}}}
	return m
}

// A host keeps its own record of each delivery beside the core's; the two
// part when the host records a generation the core refuses. Admit is the
// one admission ApplyModule decides on, asked read-only, so the host asks
// before it records and the answer is ApplyModule's: a delivery refused on
// reach is refused, delivered again at that generation it is still refused,
// and delivered again at a later generation with the same declaration it is
// still refused, so the core holds its generation and every grant on the
// page throughout (Blue, 2026-11-11: generation 7, a generation 8 refused on
// reach, a generation 9 identical to 8). A later admissible generation is
// admitted, then applied.
func TestAdmitAnswersWhatApplyModuleWouldRefuse(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, pageReachingStore(7, "read")); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	h.grant("pages", domain.InstallerRole, "remi")
	grants := h.roleGrants("pages")
	revision := h.pagesAt(acme).Revision
	held := func(want uint64) {
		t.Helper()
		m, err := h.svc.Composed(h.ctx, "pages")
		if err != nil || m.Generation != want {
			t.Fatalf("pages is composed at %d (%v), want %d", m.Generation, err, want)
		}
		if got := h.roleGrants("pages"); !slices.Equal(got, grants) {
			t.Fatalf("the grants on pages are %+v, want %+v", got, grants)
		}
		if got := h.pagesAt(acme).Revision; got != revision {
			t.Fatalf("the installation's revision moved from %d to %d", revision, got)
		}
	}

	// Generation 8 names, through a binding, what the composition does not
	// reach: refused by Admit and by ApplyModule alike, for the same reason.
	eight := pageNamingBeyondReach(8)
	err := h.svc.Admit(h.ctx, eight)
	code(t, err, domain.Denied)
	refused(t, err, `role "viewer" of pages names legacy:write through binding "legacy", which reaches it nowhere in the composition`)
	_, applied := h.svc.ApplyModule(h.ctx, eight)
	if applied == nil || applied.Error() != err.Error() {
		t.Fatalf("ApplyModule answered %v; Admit answered %v", applied, err)
	}
	held(7)

	// Delivered again, the refused generation is still refused.
	refused(t, h.svc.Admit(h.ctx, eight), "reaches it nowhere")
	_, err = h.svc.ApplyModule(h.ctx, eight)
	refused(t, err, "reaches it nowhere")
	held(7)

	// Generation 9, identical to 8: the composition still does not reach it,
	// so it is refused too, and nothing is measured against generation 7.
	nine := pageNamingBeyondReach(9)
	refused(t, h.svc.Admit(h.ctx, nine), "reaches it nowhere")
	_, err = h.svc.ApplyModule(h.ctx, nine)
	refused(t, err, "reaches it nowhere")
	held(7)

	// The generation rules are Admit's too: the held generation delivered
	// again is a replay, admitted and changing nothing; delivered with
	// another declaration, or an older generation, it is refused.
	if err := h.svc.Admit(h.ctx, pageReachingStore(7, "read")); err != nil {
		t.Fatalf("the held generation, delivered again, was refused: %v", err)
	}
	err = h.svc.Admit(h.ctx, pageReachingStore(7, "read", "write"))
	code(t, err, domain.Precondition)
	refused(t, err, "pages generation 7 is held as sha256:")
	err = h.svc.Admit(h.ctx, pageReachingStore(6, "read"))
	code(t, err, domain.Precondition)
	refused(t, err, "pages is at 7, got 6")
	err = h.svc.Admit(h.ctx, domain.Module{Name: "pages", Principal: "pages"})
	refused(t, err, "a manifest names its module, its principal and a generation")
	taken := pageReachingStore(10, "read")
	taken.Principal = "store"
	refused(t, h.svc.Admit(h.ctx, taken), `principal "store" already belongs to store`)
	held(7)

	// A later generation the composition reaches is admitted, and Admit
	// recorded nothing: the core still holds 7 until ApplyModule takes it.
	ten := pageReachingStore(10, "read")
	if err := h.svc.Admit(h.ctx, ten); err != nil {
		t.Fatalf("an admissible generation was refused: %v", err)
	}
	held(7)
	if _, err := h.svc.ApplyModule(h.ctx, ten); err != nil {
		t.Fatal(err)
	}
	held(10)
}
