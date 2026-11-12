package authority_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
)

// pageReachingStore is the module page at generation with a binding to the
// store carrying read and write, its viewer naming the store's kind with
// viewerAtStore and its installer role reading it.
func pageReachingStore(generation uint64, viewerAtStore ...string) domain.Module {
	m := pageModule(generation, true)
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(kind, "read")}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, viewerAtStore...)}
	return m
}

// approvePage approves the page's pending upgrade at acme as who, on svc,
// through Review and Install, as a solution's upgrade is approved.
func (h *harness) approvePage(svc *authority.Service, who string) (domain.Installation, error) {
	h.t.Helper()
	a, err := svc.Review(h.ctx, h.person(who), acme, "pages")
	if err != nil {
		return domain.Installation{}, err
	}
	a.OperationID = uuid.NewString()
	return svc.Install(h.ctx, h.person(who), acme, "pages", "", "", &a, nil)
}

// lastEventOn is the last event of kind on subject.
func lastEventOn(events []domain.Event, kind domain.EventKind, subject string) (domain.Event, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind == kind && events[i].Subject == subject {
			return events[i], true
		}
	}
	return domain.Event{}, false
}

func viewerGranted(grants []domain.RoleGrant, person string) bool {
	return slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == "viewer" && g.PersonID == person })
}

// A module page's installation is held at an approved reach exactly as a
// solution's is: a delivery, of the page or of a module it reaches, that
// widens what one of its roles reaches never revokes a grant and never
// widens one. The holders keep the reach approved (generation 7's), the
// installation offers an upgrade (installation.upgrade_available), and the
// upgrade is approved through Review and Install by an administrator or by a
// holder of the page's installer role; a viewer cannot approve it, and a
// later delivery that widens further still holds at 7. Once approved, the
// wider reach is issued and the grants are the same grants. A narrowing
// re-converges by itself and keeps every grant.
func TestADeliveryWideningAPageRolesReachHoldsItsInstallationAtTheApprovedReach(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(7, "read")); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	h.grant("pages", domain.InstallerRole, "remi")
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	before := h.pagesAt(acme)

	// Generation 8 widens the viewer to write at the store: the incident.
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(8, "read", "write")); err != nil {
		t.Fatal(err)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	exactly(t, h.must(h.through("remi", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	if grants := h.roleGrants("pages"); !viewerGranted(grants, "maya") || len(grants) != 2 {
		t.Fatalf("a widening touched the grants: %+v", grants)
	}
	held := h.pagesAt(acme)
	if held.Revision != before.Revision || held.Consent.Generation != 7 || held.Consent.OperationID != domain.ComposedConsent {
		t.Fatalf("the installation is not held at generation 7 by composition: %+v, was %+v", held, before)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, held); err != nil || !up {
		t.Fatalf("no upgrade offered: %v %v", up, err)
	}
	e, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, held.ID)
	if !ok || e.Detail["approved_generation"] != "7" || e.Detail["generation"] != "8" ||
		!strings.Contains(e.Detail["widened"], "role viewer reaches further") || !strings.Contains(e.Detail["widened"], "further at pages > store") {
		t.Fatalf("installation.upgrade_available: %+v %v", e, ok)
	}
	if e, ok := lastEvent(*events, domain.RoleRevoked); ok {
		t.Fatalf("a widening revoked a grant: %+v", e)
	}
	// The holder's review reads the approved reach and the pending upgrade.
	offer, err := h.svc.ReviewOffer(h.ctx, h.person("maya"), acme, "pages")
	if err != nil || !offer.UpgradeAvailable || offer.Installation.Consent.Generation != 7 {
		t.Fatalf("the holder's review: %v, %+v", err, offer.Installation)
	}

	// A viewer approves nothing; a further widening still holds at 7.
	_, err = h.approvePage(svc, "maya")
	refused(t, err, "requires an administrator or owner")
	nine := pageReachingStore(9, "read", "write")
	nine.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(kind, "read", "write")}
	if _, err := svc.ApplyModule(h.ctx, nine); err != nil {
		t.Fatal(err)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	if got := h.pagesAt(acme); got.Consent.Generation != 7 || got.Revision != before.Revision {
		t.Fatalf("a refused approval or a further delivery moved the installation: %+v", got)
	}

	// The page's installer approves the upgrade: the same grants reach 9.
	up, err := h.approvePage(svc, "remi")
	if err != nil {
		t.Fatal(err)
	}
	if up.Consent.Generation != 9 || up.Consent.OperationID == domain.ComposedConsent || up.Revision != before.Revision+1 {
		t.Fatalf("the approval did not record the upgrade: %+v", up)
	}
	if e, ok := lastEventOn(*events, domain.InstallationUpgraded, held.ID); !ok || e.Actor != "remi" || e.Detail["generation"] != "9" {
		t.Fatalf("installation.upgraded: %+v %v", e, ok)
	}
	if again, err := svc.UpgradeAvailable(h.ctx, up); err != nil || again {
		t.Fatalf("an upgrade is still offered once approved: %v %v", again, err)
	}
	if grants := h.roleGrants("pages"); !viewerGranted(grants, "maya") || len(grants) != 2 {
		t.Fatalf("the approval touched the grants: %+v", grants)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read", "write"})
	exactly(t, h.must(h.through("remi", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read", "write"})

	// A module the page reaches adding an operation the roles reach offers
	// an upgrade the same way; an administrator approves it.
	if _, err := svc.ApplyModule(h.ctx, storeAt(2, "write", false)); err != nil {
		t.Fatal(err)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || !up {
		t.Fatalf("a downstream widening offers no upgrade: %v %v", up, err)
	}
	if grants := h.roleGrants("pages"); len(grants) != 2 {
		t.Fatalf("a downstream widening touched the grants: %+v", grants)
	}
	if _, err := h.approvePage(svc, "alex"); err != nil {
		t.Fatal(err)
	}

	// A narrowing re-converges by itself and keeps every grant.
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(10, "read")); err != nil {
		t.Fatal(err)
	}
	if got := h.pagesAt(acme); got.Consent.Generation != 10 || !viewerGranted(h.roleGrants("pages"), "maya") {
		t.Fatalf("a narrowing did not re-converge with its grants: %+v", got)
	}
	if e, ok := lastEventOn(*events, domain.InstallationReconverged, held.ID); !ok || e.Detail["generation"] != "10" {
		t.Fatalf("installation.reconverged: %+v %v", e, ok)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
}

// A module page's installation its host recorded without a consent (a host
// that installs modules) is held the same: it takes composition's receipt
// when the host starts (AdoptLegacyReach) or before the next delivery, and
// a widening after that offers an upgrade instead of ending grants.
func TestAPageInstallationRecordedByItsHostIsHeldAtTheReachItHad(t *testing.T) {
	h := newHarness(t)
	cfg := h.cfg
	cfg.HostInstallsModules = true
	var events []domain.Event
	cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error { events = append(events, e); return nil }
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(7, "read")); err != nil {
		t.Fatal(err)
	}
	inst := domain.Installation{ID: authority.StableInstallationID(acme, "pages"), Organization: acme, Target: "pages", Status: domain.Active, Revision: 1, PrincipalID: authority.StablePrincipalID(acme, "pages")}
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	if err := svc.AdoptLegacyReach(h.ctx); err != nil {
		t.Fatal(err)
	}
	if e, ok := lastEvent(events, domain.InstallationReachAdopted); !ok || e.Subject != inst.ID || e.Detail["held_by"] != domain.ComposedConsent || e.Detail["approved_generation"] != "7" {
		t.Fatalf("the host's start did not hold the page's installation: %+v %v", e, ok)
	}
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(8, "read", "write")); err != nil {
		t.Fatal(err)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	if !viewerGranted(h.roleGrants("pages"), "maya") {
		t.Fatal("the widening ended the viewer's grant")
	}
	if up, err := svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || !up {
		t.Fatalf("no upgrade offered: %v %v", up, err)
	}
	if _, ok := lastEvent(events, domain.RoleRevoked); ok {
		t.Fatal("a widening revoked a grant")
	}
}

// records is a module the harness does not compose, serving recordsKind.
const recordsKind = "records.row"

func records(generation uint64) domain.Module {
	return domain.Module{Name: "records", Principal: "records", Kind: domain.KindModule, Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{sc(recordsKind, "read", "write")}}
}

// pageReachingRecords is the module page with a binding "records-rows" to
// records carrying read and write, its viewer reading there and its
// installer reading and writing.
func pageReachingRecords(generation uint64) domain.Module {
	m := pageModule(generation, true)
	m.Bindings = map[string]domain.Binding{"records-rows": {ID: "records-rows", Audience: "records", InvokeScopes: []*basev0.WorkScopeV1{sc(recordsKind, "read", "write")}}}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(recordsKind, "read", "write")}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(recordsKind, "read")}
	return m
}

// A fresh run composes its modules in no fixed order: a page composed before
// a module it reaches holds nothing there until that module lands, and then
// holds what its roles reach, with no upgrade to approve — composition takes
// the page's receipt again when the composition grows, as it took it first.
// Only a redelivery that widens a declaration offers an upgrade.
func TestAPageComposedBeforeAModuleItReachesHoldsItOnceComposed(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	if _, err := svc.ApplyModule(h.ctx, pageReachingRecords(1)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	h.grant("pages", domain.InstallerRole, "remi")
	if _, err := h.through("maya", "pages", "records-rows"); err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("a module not composed is reached: %v", err)
	}
	if _, err := svc.ApplyModule(h.ctx, records(1)); err != nil {
		t.Fatal(err)
	}
	exactly(t, h.must(h.through("maya", "pages", "records-rows")), recordsKind, "", []string{"read"})
	exactly(t, h.must(h.through("remi", "pages", "records-rows")), recordsKind, "", []string{"read", "write"})
	held := h.pagesAt(acme)
	if up, err := svc.UpgradeAvailable(h.ctx, held); err != nil || up {
		t.Fatalf("a module landing offered an upgrade: %v %v", up, err)
	}
	if e, ok := lastEventOn(*events, domain.InstallationUpgradeAvailable, held.ID); ok {
		t.Fatalf("a module landing offered an upgrade: %+v", e)
	}
	if e, ok := lastEventOn(*events, domain.InstallationReachAdopted, held.ID); !ok || e.Detail["held_by"] != domain.ComposedConsent || e.Detail["delivered"] != "records" {
		t.Fatalf("composition did not take the receipt again: %+v %v", e, ok)
	}
	// The other order holds the same.
	if _, err := svc.ApplyModule(h.ctx, pageReachingRecords(2)); err != nil {
		t.Fatal(err)
	}
	if got := h.pagesAt(acme); got.Consent.Generation != 2 || got.Consent.ReachDigest != held.Consent.ReachDigest {
		t.Fatalf("a redelivery reaching the same re-converged to %+v, was %+v", got, held)
	}
	// A redelivery of records that widens what the viewer reaches is a
	// declaration changing: it offers the upgrade and holds the viewer.
	wider := records(2)
	wider.Methods = map[string]domain.MethodPolicy{"/records.v1.Rows/List": {AnyCheckedCaller: true}}
	if _, err := svc.ApplyModule(h.ctx, wider); err != nil {
		t.Fatal(err)
	}
	if up, err := svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || !up {
		t.Fatalf("a redelivery widening the reach offered no upgrade: %v %v", up, err)
	}
	exactly(t, h.must(h.through("maya", "pages", "records-rows")), recordsKind, "", []string{"read"})
}

// A host that installs modules records the page's installation itself and
// composition takes its receipt when the host starts (AdoptLegacyReach): a
// module the page reaches composed after that is held the same way.
func TestAPageInstallationRecordedByItsHostHoldsAModuleComposedLater(t *testing.T) {
	h := newHarness(t)
	cfg := h.cfg
	cfg.HostInstallsModules = true
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, pageReachingRecords(1)); err != nil {
		t.Fatal(err)
	}
	inst := domain.Installation{ID: authority.StableInstallationID(acme, "pages"), Organization: acme, Target: "pages", Status: domain.Active, Revision: 1, PrincipalID: authority.StablePrincipalID(acme, "pages")}
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	if err := svc.AdoptLegacyReach(h.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, records(1)); err != nil {
		t.Fatal(err)
	}
	exactly(t, h.must(h.through("maya", "pages", "records-rows")), recordsKind, "", []string{"read"})
	if up, err := svc.UpgradeAvailable(h.ctx, h.pagesAt(acme)); err != nil || up {
		t.Fatalf("a module landing offered an upgrade: %v %v", up, err)
	}
}
