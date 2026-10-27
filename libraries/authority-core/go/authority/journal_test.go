package authority_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Every change of authority is journaled in the transaction that makes it,
// naming where it happened, who acted and what changed; a journal that
// refuses aborts the change.
func TestEveryChangeIsJournaledInItsOwnTransaction(t *testing.T) {
	h := newHarness(t)
	var events []domain.Event
	refuse := false
	cfg := h.cfg
	cfg.Journal = func(_ context.Context, _ authority.Tx, e domain.Event) error {
		if refuse {
			return errors.New("the journal is unavailable")
		}
		events = append(events, e)
		return nil
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	alex := h.person("alex")
	inst := h.inst(acme, "a").ID
	viewer := authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "maya"}
	steps := []struct {
		name string
		do   func() error
		want domain.Event
	}{
		{"a role granted", func() error { _, err := svc.GrantRole(h.ctx, alex, viewer); return err },
			domain.Event{Kind: domain.RoleGranted, Organization: acme, Actor: "alex", Subject: inst}},
		{"a role revoked", func() error { _, err := svc.RevokeRole(h.ctx, alex, viewer); return err },
			domain.Event{Kind: domain.RoleRevoked, Organization: acme, Actor: "alex", Subject: inst}},
		{"a delegation granted", func() error {
			_, err := svc.Delegate(h.ctx, h.person("rob"), "store", []*basev0.WorkScopeV1{sc(kind, "read")}, "a purpose")
			return err
		}, domain.Event{Kind: domain.DelegationGranted, Organization: acme, Actor: "rob"}},
		{"an installation uninstalled", func() error { return svc.Uninstall(h.ctx, alex, acme, inst) },
			domain.Event{Kind: domain.InstallationUninstalled, Organization: acme, Actor: "alex", Subject: inst}},
		{"an installation requested and activated", func() error {
			_, err := svc.Install(h.ctx, alex, acme, "a", "author", "alex", h.approval(acme, "a"), nil)
			return err
		}, domain.Event{Kind: domain.InstallationActivated, Organization: acme, Actor: "alex", Subject: inst}},
		{"a module applied", func() error {
			m := solution("d", true)
			_, err := svc.ApplyModule(h.ctx, m)
			return err
		}, domain.Event{Kind: domain.ModuleApplied, Subject: "d"}},
		{"a module withdrawn", func() error { return svc.WithdrawModule(h.ctx, "d") }, domain.Event{Kind: domain.ModuleWithdrawn, Subject: "d"}},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			before := len(events)
			if err := step.do(); err != nil {
				t.Fatal(err)
			}
			if len(events) == before {
				t.Fatal("nothing was journaled")
			}
			got := events[len(events)-1]
			if got.Kind != step.want.Kind || got.Organization != step.want.Organization || got.Actor != step.want.Actor ||
				(step.want.Subject != "" && got.Subject != step.want.Subject) {
				t.Fatalf("journaled %+v, want %+v", got, step.want)
			}
		})
	}
	if !slices.ContainsFunc(events, func(e domain.Event) bool { return e.Kind == domain.InstallationRequested }) {
		t.Fatal("the pending attempt was not journaled")
	}

	t.Run("a journal that refuses aborts the change", func(t *testing.T) {
		refuse = true
		defer func() { refuse = false }()
		_, err := svc.GrantRole(h.ctx, alex, authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "remi"})
		if err == nil {
			t.Fatal("the grant committed without its journal entry")
		}
		grants, err := h.svc.ListRoleGrants(h.ctx, alex, acme, inst)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.PersonID == "remi" }) {
			t.Fatal("the refused journal left the grant behind")
		}
	})
}
