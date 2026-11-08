package authority_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// journaled wraps the harness core with a journal that records every event.
func journaled(h *harness) (*authority.Service, *[]domain.Event) {
	h.t.Helper()
	var events []domain.Event
	cfg := h.cfg
	cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error { events = append(events, e); return nil }
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc, &events
}

func lastEvent(events []domain.Event, kind domain.EventKind) (domain.Event, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind == kind {
			return events[i], true
		}
	}
	return domain.Event{}, false
}

func (h *harness) stored(org, target string) domain.Installation {
	h.t.Helper()
	inst, err := h.svc.Installations(h.ctx, h.admin(org), org)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, i := range inst {
		if i.Target == target {
			return i
		}
	}
	h.t.Fatalf("%s is not installed at %s", target, org)
	return domain.Installation{}
}

// A redelivery that asks nothing new of an organization re-converges its
// active installation without a click: the consent moves to the new
// generation, the revision moves (what was issued under the old generation
// ends), every role grant is kept, and the change is journaled.
func TestARedeliveryAskingNothingNewReconvergesAnActiveInstallation(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	h.grant("a", "viewer", "maya")
	h.grant("a", "editor", "remi")
	before := h.stored(acme, "a")
	if before.Consent.Generation != 1 || before.Consent.Digest == "" {
		t.Fatalf("the install recorded no approved generation and digest: %+v", before.Consent)
	}
	viewer := h.must(h.root("maya", "a"))

	// Generation 2 cuts the viewer's reach and changes nothing else; the
	// installer's and the author's roles are as approved.
	narrowed := solution("a", true)
	narrowed.Generation = 2
	narrowed.Roles["viewer"] = []*basev0.WorkScopeV1{sc("a.note", "read")}
	if _, err := svc.ApplyModule(h.ctx, narrowed); err != nil {
		t.Fatal(err)
	}
	after := h.stored(acme, "a")
	if after.Status != domain.Active || after.Consent.Generation != 2 || after.Consent.Digest == before.Consent.Digest || after.Revision != before.Revision+1 {
		t.Fatalf("the installation did not re-converge on generation 2: %+v", after)
	}
	if decide.UpgradeAvailable(after, narrowed) {
		t.Fatal("a re-converged installation offers an upgrade")
	}
	if grants := h.roleGrants("a"); len(grants) != 2 {
		t.Fatalf("the redelivery touched the grants: %v", grants)
	}
	e, ok := lastEvent(*events, domain.InstallationReconverged)
	if !ok || e.Subject != after.ID || e.Organization != acme || e.Detail["generation"] != "2" || e.Detail["approved_generation"] != "1" {
		t.Fatalf("installation.reconverged was not journaled: %+v %v", e, ok)
	}
	if _, ok := lastEvent(*events, domain.InstallationUpgradeAvailable); ok {
		t.Fatal("a subset redelivery journaled an upgrade")
	}
	if err := h.check(viewer); err == nil {
		t.Fatal("a capability issued under the wider generation survived the redelivery")
	}
	viewer = h.must(h.root("maya", "a"))
	exactly(t, viewer, "a.note", h.principal(acme, "a"), []string{"read"})
	// The other organization's installation re-converged too.
	if g := h.stored(globex, "a"); g.Consent.Generation != 2 {
		t.Fatalf("globex's installation stayed at %+v", g.Consent)
	}
	// A generation bump alone (the same offer) re-converges as well.
	same := narrowed
	same.Generation = 3
	if _, err := svc.ApplyModule(h.ctx, same); err != nil {
		t.Fatal(err)
	}
	if got := h.stored(acme, "a"); got.Consent.Generation != 3 {
		t.Fatalf("an unchanged offer did not re-converge: %+v", got.Consent)
	}
	// A fresh approval of the offer the consent already stands on is not an
	// upgrade: the installation is already installed, and its grants stay.
	_, err := svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "alex", h.approval(acme, "a"), nil)
	if !errors.Is(err, domain.ErrAlreadyInstalled) {
		t.Fatalf("want already installed, got %v", err)
	}
	if grants := h.roleGrants("a"); len(grants) != 2 {
		t.Fatalf("a refused install touched the grants: %v", grants)
	}
}

// A redelivery that asks more leaves the installation on its consent, active
// with its grants, and offers an upgrade naming what widened. Install with a
// fresh review approves the new offer in place: active throughout, grants
// kept, consent and revision moved, no uninstall.
func TestARedeliveryAskingMoreOffersAnUpgradeThatKeepsGrants(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	h.grant("a", "viewer", "maya")
	h.grantTeam("a", "editor", "team")
	before := h.stored(acme, "a")

	wider := solution("a", true)
	wider.Generation = 2
	wider.Roles["publisher"] = []*basev0.WorkScopeV1{sc("a.note", "read", "write")}
	wider.Roles["viewer"] = []*basev0.WorkScopeV1{sc("a.note", "read", "write"), sc(kind, "read"), sc(legacyKind, "read")}
	if _, err := svc.ApplyModule(h.ctx, wider); err != nil {
		t.Fatal(err)
	}
	held := h.stored(acme, "a")
	if held.Status != domain.Active || held.Consent != before.Consent || held.Revision != before.Revision {
		t.Fatalf("a widening moved the installation: %+v, was %+v", held, before)
	}
	if !decide.UpgradeAvailable(held, wider) {
		t.Fatal("the installation does not offer the upgrade")
	}
	e, ok := lastEvent(*events, domain.InstallationUpgradeAvailable)
	if !ok || e.Subject != held.ID || !strings.Contains(e.Detail["widened"], "role publisher added") || !strings.Contains(e.Detail["widened"], "role viewer reaches further") {
		t.Fatalf("installation.upgrade_available does not name what widened: %+v %v", e, ok)
	}
	if grants := h.roleGrants("a"); len(grants) != 2 {
		t.Fatalf("the widening touched the grants: %v", grants)
	}
	// Until the upgrade is approved, holders hold what the approved roles
	// grant them, and the new role cannot be granted.
	viewer := h.must(h.root("maya", "a"))
	exactly(t, viewer, "a.note", h.principal(acme, "a"), []string{"read", "write"})
	if _, err := h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: held.ID, Role: "publisher", PersonID: "remi"}); err != nil {
		t.Fatalf("the delivered role is granted on the standing installation: %v", err)
	}

	// The upgrade: review, then Install on the active installation.
	approval := h.approval(acme, "a")
	if approval.Generation != 2 || approval.ExpectedRevision != held.Revision {
		t.Fatalf("the review names %+v, want generation 2 at revision %d", approval, held.Revision)
	}
	upgraded, err := svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "alex", approval, func(context.Context, domain.Installation) error {
		t.Fatal("an upgrade ran the install step")
		return nil
	})
	if err != nil || upgraded.Status != domain.Active || upgraded.Consent.Generation != 2 || upgraded.Revision != held.Revision+1 || upgraded.PrincipalID != held.PrincipalID {
		t.Fatalf("upgrade: %+v %v", upgraded, err)
	}
	if decide.UpgradeAvailable(upgraded, wider) {
		t.Fatal("an upgraded installation still offers the upgrade")
	}
	if grants := h.roleGrants("a"); len(grants) != 3 {
		t.Fatalf("the upgrade touched the grants: %v", grants)
	}
	if e, ok := lastEvent(*events, domain.InstallationUpgraded); !ok || e.Subject != upgraded.ID || e.Actor != "alex" || e.Detail["generation"] != "2" {
		t.Fatalf("installation.upgraded was not journaled: %+v %v", e, ok)
	}
	if err := h.check(viewer); err == nil {
		t.Fatal("a capability issued before the upgrade survived it")
	}
	publisher := h.must(h.root("remi", "a"))
	exactly(t, publisher, "a.note", h.principal(acme, "a"), []string{"read", "write"})
	// The same approval again is the unchanged retry; another fresh one is
	// already installed.
	again, err := svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "alex", approval, nil)
	if err != nil || again.Revision != upgraded.Revision {
		t.Fatalf("retry: %+v %v", again, err)
	}
	_, err = svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "alex", h.approval(acme, "a"), nil)
	if !errors.Is(err, domain.ErrAlreadyInstalled) {
		t.Fatalf("want already installed, got %v", err)
	}
	// Globex, which did not approve, still offers the upgrade.
	if g := h.stored(globex, "a"); !decide.UpgradeAvailable(g, wider) {
		t.Fatalf("globex's installation does not offer the upgrade: %+v", g)
	}
}

// An installation whose consent is behind the delivered generation cannot be
// proven to cover the next one, whatever that one narrows: it keeps offering
// its upgrade until an administrator approves.
func TestAnInstallationBehindTheDeliveryStaysBehindUntilUpgraded(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	wider := solution("a", true)
	wider.Generation = 2
	wider.Roles["publisher"] = []*basev0.WorkScopeV1{sc("a.note", "read", "write")}
	if _, err := svc.ApplyModule(h.ctx, wider); err != nil {
		t.Fatal(err)
	}
	back := solution("a", true)
	back.Generation = 3
	if _, err := svc.ApplyModule(h.ctx, back); err != nil {
		t.Fatal(err)
	}
	inst := h.stored(acme, "a")
	if inst.Consent.Generation != 1 || !decide.UpgradeAvailable(inst, back) {
		t.Fatalf("an installation behind the delivery re-converged: %+v", inst)
	}
	if e, ok := lastEvent(*events, domain.InstallationUpgradeAvailable); !ok || !strings.Contains(e.Detail["widened"], "approved generation 1 is behind") {
		t.Fatalf("the lag is not named: %+v %v", e, ok)
	}
	if up, err := svc.Install(h.ctx, h.admin(acme), acme, "a", "author", "alex", h.approval(acme, "a"), nil); err != nil || up.Consent.Generation != 3 {
		t.Fatalf("upgrade: %+v %v", up, err)
	}
}

// Grants end by RevokeRole and by an uninstall alone. An install never deletes
// one: an uninstalled installation reinstalls with the grants its uninstall
// cleared, and a pending attempt superseded by a fresh approval keeps what it
// holds.
func TestGrantsEndOnlyByRevokeAndUninstall(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	h.grant("a", "editor", "remi")
	h.revoke("a", "viewer", "maya", "")
	if grants := h.roleGrants("a"); len(grants) != 1 || grants[0].PersonID != "remi" {
		t.Fatalf("revoke: %v", grants)
	}
	id := h.inst(acme, "a").ID
	if err := h.svc.Uninstall(h.ctx, h.admin(acme), acme, id); err != nil {
		t.Fatal(err)
	}
	var left []domain.RoleGrant
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) { left, err = tx.RoleGrants(id); return err }); err != nil || len(left) != 0 {
		t.Fatalf("uninstall left grants %v (%v)", left, err)
	}
	again := h.install(acme, "a")
	if again.ID != id || again.Status != domain.Active || len(h.roleGrants("a")) != 0 {
		t.Fatalf("reinstall: %+v, grants %v", again, h.roleGrants("a"))
	}
	h.grant("a", "viewer", "maya")
	if names := func() []string {
		var out []string
		for _, g := range h.roleGrants("a") {
			out = append(out, g.Role+":"+g.PersonID)
		}
		slices.Sort(out)
		return out
	}(); !slices.Equal(names, []string{"viewer:maya"}) {
		t.Fatalf("grants after reinstall: %v", names)
	}
}
