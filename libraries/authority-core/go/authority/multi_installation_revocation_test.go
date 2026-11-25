package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A capability is sealed to one installation, its last actor's, and its path
// may name others: a person's call through solution A, then the store's own
// hop, is sealed to the store's installation and holds what the person's role
// on A gave. A module that reads what admitted the call, never asking which
// resources the caller holds now, relies on Check alone to end it. So a role
// lost on an installation the capability is not sealed to must end it too.

// deeper is a person's call through solution a, and the store's own hop on
// it: sealed to the store's installation, holding what the role on a gave.
func (h *harness) deeper(person string) authority.Issued {
	h.t.Helper()
	out := h.must(h.hop(h.must(h.through(person, "a", "store")), "self"))
	if sealed, role := out.Context.GetSeal().GetInstallationId(), h.inst(acme, "a").ID; sealed == role {
		h.t.Fatalf("the hop is sealed to %s, the installation the role is on: this proves nothing about another one", sealed)
	}
	if err := h.check(out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func TestARoleRevokedOnAnInstallationTheCapabilityIsNotSealedToEndsIt(t *testing.T) {
	t.Parallel()
	t.Run("a person's role", func(t *testing.T) {
		h := newHarness(t)
		h.grant("a", "user", "maya")
		h.grant("b", "user", "maya")
		h.grant("a", "user", "remi")
		deeper, other := h.deeper("maya"), h.deeper("remi")
		throughB := h.must(h.through("maya", "b", "store"))
		h.revoke("a", "user", "maya", "")
		if err := h.check(deeper); err == nil {
			t.Fatal("a hop sealed to the store's installation still holds what the role revoked on a gave")
		}
		if _, err := h.svc.ListResources(h.ctx, deeper.Token, "store", kind, "read"); err == nil {
			t.Fatal("the revoked role's hop is still answered its resources")
		}
		for name, c := range map[string]authority.Issued{"another person's hop through a": other, "the same person's call through b": throughB} {
			if err := h.check(c); err != nil {
				t.Fatalf("revoking maya's role on a ended %s: %v", name, err)
			}
		}
		h.grant("a", "user", "maya")
		if err := h.check(deeper); err == nil {
			t.Fatal("a re-grant revived the old hop")
		}
		h.deeper("maya")
	})
	t.Run("one of two roles, the other still held", func(t *testing.T) {
		h := newHarness(t)
		h.grant("a", "user", "maya")
		h.grant("a", "admin", "maya")
		deeper := h.deeper("maya")
		h.revoke("a", "admin", "maya", "")
		if err := h.check(deeper); err == nil {
			t.Fatal("a hop holding what the revoked admin role gave is still admitted")
		}
		exactly(t, h.deeper("maya"), kind, h.principal(acme, "a"), read)
	})
	t.Run("a team's role", func(t *testing.T) {
		h := newHarness(t)
		h.grantTeam("a", "user", "team")
		h.grant("a", "user", "maya")
		deeper, other := h.deeper("tam"), h.deeper("maya")
		h.revoke("a", "user", "", "team")
		if err := h.check(deeper); err == nil {
			t.Fatal("a member's hop sealed to the store's installation survived the team's revoke on a")
		}
		if err := h.check(other); err != nil {
			t.Fatalf("revoking the team's role ended a hop of someone who is not in it: %v", err)
		}
	})
	t.Run("the role of a page, two hops on", func(t *testing.T) {
		h := newHarness(t)
		reachComposition(t, h, true)
		h.grant("wiki", "user", "maya")
		h.grant("builder", "user", "maya")
		atAgent := h.must(h.page("maya", "wiki", "agent"))
		evidence := h.must(h.onward(atAgent, "evidence"))
		if sealed := evidence.Context.GetSeal().GetInstallationId(); sealed == h.inst(acme, "wiki").ID {
			t.Fatalf("the agent's hop is sealed to %s, the installation the role is on", sealed)
		}
		throughBuilder := h.must(h.page("maya", "builder", "agent"))
		h.revoke("wiki", "user", "maya", "")
		for name, c := range map[string]authority.Issued{"the page's call at the agent": atAgent, "the agent's hop to the documents": evidence} {
			if err := h.check(c); err == nil {
				t.Fatalf("%s still holds what the role revoked on the wiki gave", name)
			}
		}
		if err := h.check(throughBuilder); err != nil {
			t.Fatalf("revoking the wiki's role ended the same person's call through the builder: %v", err)
		}
	})
	t.Run("no call holds the role on the solution it is addressed to from another installation", func(t *testing.T) {
		// The one other place a role bounds a path is its audience: a call
		// at a solution holds the person's role there. Were one issued from
		// another target, it would be sealed to that target's installation,
		// which a revoke on the audience's does not move (sealedAlong follows
		// bindings forward only). None is: each solution's role selects its
		// own installation's data, and the two never meet. A change that
		// issues one must move the epoch on the installations binding to the
		// audience too.
		h := newHarness(t)
		front := domain.Module{Name: "front", Principal: "front", Kind: domain.KindSolution, Generation: 1, OwnerAware: true,
			ResourceKinds: []*basev0.WorkScopeV1{sc("front.note", "read")},
			Bindings:      map[string]domain.Binding{"a": {ID: "a", Audience: "a", InvokeScopes: []*basev0.WorkScopeV1{sc("a.note", "read")}}},
			Roles: map[string][]*basev0.WorkScopeV1{domain.AdminRole: {sc("front.note", "read")},
				domain.UserRole: {sc("front.note", "read"), sc("a.note", "read")}}}
		if _, err := h.svc.ApplyModule(h.ctx, front); err != nil {
			t.Fatal(err)
		}
		h.install(acme, "front")
		h.grant("front", "user", "maya")
		h.grant("a", "user", "maya")
		_, err := h.through("maya", "front", "a")
		refused(t, err, `holds nothing at a through binding "a"`)
	})
	t.Run("a team left", func(t *testing.T) {
		h := newHarness(t)
		h.grantTeam("a", "user", "team")
		deeper := h.deeper("tam")
		h.store.PutPerson(domain.Person{ID: "tam", Organization: acme})
		if err := h.svc.PersonChanged(h.ctx, "tam"); err != nil {
			t.Fatal(err)
		}
		if err := h.check(deeper); err == nil {
			t.Fatal("a hop sealed to the store's installation survived its person leaving the team that gave the role")
		}
	})
}

// The other ways a path's installation changes move the organisation's
// authorization revision, which every capability of the organisation carries:
// they end a hop sealed elsewhere already.
func TestAnInstallationChangedOnThePathEndsAHopSealedElsewhere(t *testing.T) {
	t.Parallel()
	t.Run("a resource of the path's installation detached", func(t *testing.T) {
		h := newHarness(t)
		h.grant("a", "admin", "maya")
		creator := h.must(h.through("maya", "a", "store"))
		if _, err := h.svc.AttachResource(h.ctx, authority.AttachmentRequest{Token: creator.Token, Store: authority.Workload{Module: "store"}, Kind: kind, ResourceID: "doc-1"}); err != nil {
			t.Fatal(err)
		}
		deeper := h.deeper("maya")
		if _, err := h.svc.DetachResource(h.ctx, authority.Workload{Module: "store"}, acme, kind, "doc-1"); err != nil {
			t.Fatal(err)
		}
		if err := h.check(deeper); err == nil {
			t.Fatal("a hop sealed to the store's installation survived the detachment on a")
		}
	})
	t.Run("the path's solution delivered narrower", func(t *testing.T) {
		h := newHarness(t)
		h.grant("a", "user", "maya")
		deeper := h.deeper("maya")
		narrowed := solution("a", true)
		narrowed.Generation = 2
		narrowed.Roles[domain.UserRole] = narrowed.Roles[domain.UserRole][:1]
		if _, err := h.svc.ApplyModule(h.ctx, narrowed); err != nil {
			t.Fatal(err)
		}
		if err := h.check(deeper); err == nil {
			t.Fatal("a hop sealed to the store's installation survived the narrowing of the role on a")
		}
	})
	t.Run("the path's solution uninstalled", func(t *testing.T) {
		h := newHarness(t)
		h.grant("a", "user", "maya")
		deeper := h.deeper("maya")
		if err := h.svc.UninstallAsHost(h.ctx, acme, h.inst(acme, "a").ID); err != nil {
			t.Fatal(err)
		}
		if err := h.check(deeper); err == nil {
			t.Fatal("a hop sealed to the store's installation survived the uninstall of a")
		}
	})
}
