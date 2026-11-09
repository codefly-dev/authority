package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const (
	storeRead  = "/store.v1.Store/Read"
	storePurge = "/store.v1.Store/Purge"
)

// storeAt is the harness's store module redelivered at generation with
// method policies: Read requires read, Purge requires purge (admin unless
// relaxed), and its binding to the legacy store unless cut.
func storeAt(generation uint64, purge string, legacy bool) domain.Module {
	m := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: generation, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")},
		Bindings: map[string]domain.Binding{
			"self": {ID: "self", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read")}},
		},
		Methods: map[string]domain.MethodPolicy{
			storeRead:  {Requires: []*basev0.WorkScopeV1{sc(kind, "read")}},
			storePurge: {Requires: []*basev0.WorkScopeV1{sc(kind, purge)}},
		}}
	if legacy {
		m.Bindings["legacy"] = domain.Binding{ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}
	}
	return m
}

// reachHarness is the harness with the store declaring its methods, the
// administrator's consent to a's offer taken on that composition, and maya
// holding a's author role.
func reachHarness(t *testing.T) *harness {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, storeAt(2, "admin", true)); err != nil {
		t.Fatal(err)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || !up {
		t.Fatalf("the store declaring its methods widened a's reach without an upgrade offered: %v %v", up, err)
	}
	h.install(acme, "a") // the administrator approves the reach
	h.grant("a", "author", "maya")
	return h
}

func (h *harness) callStore(parent authority.Issued, method string) error {
	_, _, _, err := h.svc.CheckMethod(h.ctx, parent.Token, "store", method, false)
	return err
}

// A module's redelivery that widens a solution's reach offers an upgrade:
// the store relaxing Purge to what a's author holds makes a's installation
// offer one, though a did not change; until an administrator approves it,
// holders keep the approved reach (Purge refused through a, Read admitted,
// the holder's review lists the approved reach); once approved, Purge is
// admitted.
func TestAModulesRedeliveryThatWidensASolutionsReachOffersAnUpgrade(t *testing.T) {
	h := reachHarness(t)
	before := h.stored(acme, "a")
	at := h.must(h.through("maya", "a", "store"))
	if err := h.callStore(at, storeRead); err != nil {
		t.Fatal(err)
	}
	refused(t, h.callStore(at, storePurge), "requires "+kind+":admin")

	replica := domain.Module{Name: "replica", Principal: "replica", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, replica); err != nil {
		t.Fatal(err)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || up {
		t.Fatalf("a module nothing reaches widened a's reach: %v %v", up, err)
	}
	wider := storeAt(3, "write", true)
	wider.Bindings["replica"] = domain.Binding{ID: "replica", Audience: "replica", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, wider); err != nil {
		t.Fatal(err)
	}
	inst := h.stored(acme, "a")
	if up, err := h.svc.UpgradeAvailable(h.ctx, inst); err != nil || !up {
		t.Fatalf("a module widening a's reach offers no upgrade: %v %v", up, err)
	}
	if inst.Consent != before.Consent || inst.Revision != before.Revision {
		t.Fatalf("the widening moved a's consent: %+v, was %+v", inst.Consent, before.Consent)
	}
	at = h.must(h.through("maya", "a", "store"))
	if err := h.callStore(at, storeRead); err != nil {
		t.Fatalf("the approved reach was cut: %v", err)
	}
	refused(t, h.callStore(at, storePurge), "beyond the reach its solution's installation approved")
	_, err := h.hop(at, "replica")
	refused(t, err, "holds nothing at replica")
	offer, err2 := h.svc.ReviewOffer(h.ctx, h.person("maya"), acme, "a")
	if err2 != nil || !offer.UpgradeAvailable {
		t.Fatalf("the holder's review: %v, upgrade %v", err2, offer.UpgradeAvailable)
	}
	if rows := offer.Reach["author"]; !slices.ContainsFunc(rows, func(r domain.ReachRow) bool {
		return r.Module == "store" && slices.Equal(r.Operations, []string{storeRead})
	}) {
		t.Fatalf("the holder reads a reach other than the approved one: %+v", rows)
	}
	admin, err := h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "a")
	if err != nil || !slices.ContainsFunc(admin.Reach["author"], func(r domain.ReachRow) bool {
		return r.Module == "store" && slices.Contains(r.Operations, storePurge)
	}) {
		t.Fatalf("the administrator's review does not show the wider reach: %+v (%v)", admin.Reach["author"], err)
	}
	// A consent tuple reviewed before the widening no longer installs.
	stale := *h.approval(acme, "a")
	stale.ReachDigest = before.Consent.ReachDigest
	_, err = h.svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "alex", &stale, nil)
	refused(t, err, "INSTALLATION_APPROVAL_REACH_CHANGED")

	up := h.install(acme, "a")
	if up.ID != inst.ID || up.Consent.ReachDigest == before.Consent.ReachDigest {
		t.Fatalf("the upgrade did not record the wider reach: %+v", up.Consent)
	}
	if again, err := h.svc.UpgradeAvailable(h.ctx, up); err != nil || again {
		t.Fatalf("an upgrade is still offered once approved: %v %v", again, err)
	}
	at = h.must(h.through("maya", "a", "store"))
	if err := h.callStore(at, storePurge); err != nil {
		t.Fatalf("the approved wider reach is refused: %v", err)
	}
	if _, err := h.hop(at, "replica"); err != nil {
		t.Fatalf("the approved path to the replica is refused: %v", err)
	}
	if grants := h.roleGrants("a"); !slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == "author" && g.PersonID == "maya" }) {
		t.Fatalf("the upgrade lost the grant: %v", grants)
	}
}

// A module's redelivery that narrows a solution's reach re-converges: the
// store requiring write to Read narrows what a's viewer reaches there (read
// alone); a's consent advances to the narrower reach with no click, its
// revision moves (what was issued under the wider reach ends), no upgrade
// is offered, and the grants are kept.
func TestAModulesRedeliveryThatNarrowsASolutionsReachReconverges(t *testing.T) {
	h := reachHarness(t)
	h.grant("a", "viewer", "remi")
	before := h.stored(acme, "a")
	issued := h.must(h.root("remi", "a"))
	stricter := storeAt(3, "admin", true)
	stricter.Methods[storeRead] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, stricter); err != nil {
		t.Fatal(err)
	}
	inst := h.stored(acme, "a")
	if inst.Consent.ReachDigest == before.Consent.ReachDigest || inst.Revision != before.Revision+1 || inst.Consent.OperationID != before.Consent.OperationID {
		t.Fatalf("a's consent did not re-converge on the narrower reach: %+v, was %+v", inst, before)
	}
	reach, err := decide.DecodeReach(inst.Consent.Reach)
	if err != nil || slices.ContainsFunc(reach["viewer"], func(r domain.ReachRow) bool { return r.Module == "store" && slices.Contains(r.Operations, storeRead) }) {
		t.Fatalf("the approved reach still lists what the viewer no longer reaches: %+v (%v)", reach["viewer"], err)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, inst); err != nil || up {
		t.Fatalf("a narrowing offers an upgrade: %v %v", up, err)
	}
	if err := h.check(issued); err == nil {
		t.Fatal("a capability issued under the wider reach outlived the narrowing")
	}
	if grants := h.roleGrants("a"); len(grants) != 2 {
		t.Fatalf("the narrowing touched the grants: %v", grants)
	}
	exactly(t, h.must(h.root("remi", "a")), "a.note", h.principal(acme, "a"), []string{"read"})
}

// A call narrowed below its role is held to the approved policy on what it
// carries itself: with Purge approved as requiring write, maya's capability
// through a asked read alone is refused Purge; the store relaxing Purge to
// read offers an upgrade, and until an administrator approves it the
// narrowed capability is still refused, though the role's approved reach
// (read and write) satisfies the approved policy. Once approved, it is
// admitted.
func TestANarrowedCallIsHeldToTheApprovedPolicyOnItsOwnScopes(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, storeAt(2, "write", true)); err != nil {
		t.Fatal(err)
	}
	h.install(acme, "a")
	h.grant("a", "author", "maya")
	full := h.must(h.through("maya", "a", "store"))
	if err := h.callStore(full, storePurge); err != nil {
		t.Fatalf("the author's full capability is refused the approved Purge: %v", err)
	}
	readOnly := owned(kind, h.principal(acme, "a"), []string{"read"})
	narrowed := h.must(h.through("maya", "a", "store", readOnly))
	refused(t, h.callStore(narrowed, storePurge), "requires "+kind+":write")

	if _, err := h.svc.ApplyModule(h.ctx, storeAt(3, "read", true)); err != nil {
		t.Fatal(err)
	}
	if up, err := h.svc.UpgradeAvailable(h.ctx, h.stored(acme, "a")); err != nil || !up {
		t.Fatalf("relaxing Purge offers no upgrade: %v %v", up, err)
	}
	refused(t, h.callStore(narrowed, storePurge), "beyond the reach its solution's installation approved")
	if err := h.callStore(narrowed, storeRead); err != nil {
		t.Fatalf("the narrowed capability lost the approved Read: %v", err)
	}

	h.install(acme, "a") // the administrator approves the relaxation
	narrowed = h.must(h.through("maya", "a", "store", readOnly))
	if err := h.callStore(narrowed, storePurge); err != nil {
		t.Fatalf("the approved relaxation is refused: %v", err)
	}
}
