package authority_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A delivery never widens what an existing grant means (RBAC audit B2). A
// grant is an administrator's approval of what the role meant when it was
// given; a later delivery that gives the same name a wider meaning holds the
// grant at that meaning and offers the upgrade, and a withdrawal ends the
// grant, two ways it used to widen them silently (a third, a solution
// installed by trusted host setup, follows its delivery by design).

func journalingService(h *harness) (*authority.Service, *[]domain.Event) {
	var events []domain.Event
	cfg := h.cfg
	cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error {
		events = append(events, e)
		return nil
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc, &events
}

func scopeText(scopes []*basev0.WorkScopeV1) string {
	var out []string
	for _, s := range scopes {
		out = append(out, s.GetResourceKind()+":"+strings.Join(s.GetActions(), "+"))
	}
	return strings.Join(out, " | ")
}

func kinds(events []domain.Event) []domain.EventKind {
	var out []domain.EventKind
	for _, e := range events {
		out = append(out, e.Kind)
	}
	return out
}

// A module page's role widened on the page's own kind holds its holders at
// what the role meant when it was granted: the grant stays, the wider
// meaning waits for the upgrade's approval, and the approval is the
// administrator's review of the delivered offer, never a regrant.
func TestModulePageRoleWidenedOnItsOwnKindHoldsItsHoldersAtTheApprovedRole(t *testing.T) {
	h := newHarness(t)
	svc, events := journalingService(h)
	if _, err := svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	inst := h.pagesAt(acme)
	if _, err := svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	write := authority.IssueRequest{Audience: "pages", Scopes: []*basev0.WorkScopeV1{sc("pages.note", "write")}}
	m := pageModule(2, true)
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	if _, err := svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.IssueForPerson(h.ctx, h.person("maya"), write); err == nil {
		t.Fatalf("a viewer granted read holds write after a delivery widened the role: %s", scopeText(got.Context.GetAuthorityScopes()))
	}
	if _, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages", Scopes: []*basev0.WorkScopeV1{sc("pages.note", "read")}}); err != nil {
		t.Fatalf("the viewer's grant no longer answers at the approved role: %v", err)
	}
	if !slices.Contains(kinds(*events), domain.InstallationUpgradeAvailable) || slices.Contains(kinds(*events), domain.RoleRevoked) {
		t.Fatalf("the widening is not offered as an upgrade, or revoked a grant: %v", kinds(*events))
	}
	if _, err := h.approvePage(svc, "alex"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IssueForPerson(h.ctx, h.person("maya"), write); err != nil {
		t.Fatalf("the approved wider role is not held: %v", err)
	}
}

func TestGrantDoesNotSurviveTheWithdrawalOfItsModule(t *testing.T) {
	h := newHarness(t)
	cfg := h.cfg
	cfg.HostInstallsModules = true
	var events []domain.Event
	cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error { events = append(events, e); return nil }
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	inst := domain.Installation{ID: authority.StableInstallationID(acme, "pages"), Organization: acme, Target: "pages", Status: domain.Active, Revision: 1, PrincipalID: authority.StablePrincipalID(acme, "pages")}
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.WithdrawModule(h.ctx, "pages"); err != nil {
		t.Fatal(err)
	}
	var grants []domain.RoleGrant
	var revision uint64
	_ = h.store.Read(h.ctx, func(tx authority.Tx) error {
		grants, _ = tx.RoleGrants(inst.ID)
		got, err := tx.Installation(inst.ID)
		revision = got.Revision
		return err
	})
	if len(grants) != 0 {
		t.Fatalf("grants survive the withdrawal of their module: %+v", grants)
	}
	if revision <= inst.Revision {
		t.Fatalf("the installation's revision did not move: %d", revision)
	}
	if !slices.Contains(kinds(events), domain.RoleRevoked) {
		t.Fatalf("the ended grant is not journaled: %v", kinds(events))
	}
	m := pageModule(3, true)
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	if _, err := svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages", Scopes: []*basev0.WorkScopeV1{sc("pages.note", "write")}}); err == nil {
		t.Fatalf("a grant from before the withdrawal holds the redelivered role: %s", scopeText(got.Context.GetAuthorityScopes()))
	}
}

// A capability lives fifteen minutes unless a host says otherwise: the hour
// the Work Context library defaults to is what a revoked scope grant used to
// outlive.
func TestCapabilityLifetimeCeilingIsFifteenMinutes(t *testing.T) {
	h := newHarness(t)
	cfg := h.cfg
	cfg.MaxTTL = 0
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	inst := h.pagesAt(acme)
	if _, err := svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages", TTL: 2 * time.Hour})
	if err == nil {
		if ttl := time.Unix(got.Context.GetExpiresAtUnix(), 0).Sub(h.now); ttl > authority.DefaultMaxTTL {
			t.Fatalf("a capability lives %s", ttl)
		}
	}
	got, err = svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages"})
	if err != nil {
		t.Fatal(err)
	}
	if ttl := time.Unix(got.Context.GetExpiresAtUnix(), 0).Sub(h.now); ttl != authority.DefaultMaxTTL {
		t.Fatalf("a capability asked for no lifetime lives %s, not %s", ttl, authority.DefaultMaxTTL)
	}
}
