package authority_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// hookStore runs after once, right after the Read that finds it armed
// returns: a narrowing the host commits between the core's decision and its
// mint.
type hookStore struct {
	*memstore.Store
	mu    sync.Mutex
	after func()
}

func (h *hookStore) Read(ctx context.Context, fn func(authority.Tx) error) error {
	err := h.Store.Read(ctx, fn)
	h.mu.Lock()
	f := h.after
	h.after = nil
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return err
}

func (h *hookStore) arm(f func()) {
	h.mu.Lock()
	h.after = f
	h.mu.Unlock()
}

// A narrowing the host commits between an issue's decision and its mint is
// never handed out: the capability decided under the withdrawn consent is
// refused at issuance, on every path, by the revision fence.
func TestANarrowingBetweenDecisionAndMintIsNeverHandedOut(t *testing.T) {
	for _, path := range []string{"workload", "child"} {
		t.Run(path, func(t *testing.T) {
			h := newHarness(t)
			cfg := h.cfg
			cfg.HostInstallsModules = true
			mem := memstore.New()
			store := &hookStore{Store: mem}
			svc, err := authority.New(store, cfg)
			if err != nil {
				t.Fatal(err)
			}
			mem.PutOrganization(domain.Organization{ID: acme, Name: acme})
			mem.PutOrgRole(domain.OrgRole{Organization: acme, Name: "reader", Scopes: []domain.RoleScope{{Kind: legacyKind, Actions: []string{"read", "write"}}, {Kind: kind, Actions: []string{"read"}}}})
			mem.PutPerson(domain.Person{ID: "alex", Organization: acme, Roles: []string{"reader"}})
			relayScopes := []*basev0.WorkScopeV1{sc(legacyKind, "read", "write")}
			for _, m := range []domain.Module{
				{Name: "relay", Principal: "relay", Kind: domain.KindModule, Generation: 1, ResourceKinds: relayScopes},
				{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 1, ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read")},
					Bindings: map[string]domain.Binding{"relay": {ID: "relay", Audience: "relay", InvokeScopes: relayScopes, HeadlessScopes: relayScopes}}},
			} {
				if _, err := svc.ApplyModule(h.ctx, m); err != nil {
					t.Fatal(err)
				}
			}
			put := func(revision uint64, bindings map[string]domain.Binding) {
				if err := mem.Write(h.ctx, func(tx authority.Tx) error {
					return tx.PutInstallation(domain.Installation{ID: "st-1", Organization: acme, Target: "store", Status: domain.Active, Revision: revision, Bindings: bindings})
				}); err != nil {
					t.Fatal(err)
				}
			}
			put(1, map[string]domain.Binding{"relay": {ID: "relay", InvokeScopes: relayScopes, HeadlessScopes: relayScopes}})
			narrow := func() { put(2, map[string]domain.Binding{}) }
			if path == "workload" {
				store.arm(narrow)
				_, err = svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "relay", Organization: acme})
			} else {
				parent, perr := svc.IssueForPerson(h.ctx, authority.Person{ID: "alex", Organization: acme, SessionID: "s"}, authority.IssueRequest{Audience: "store"})
				if perr != nil {
					t.Fatal(perr)
				}
				// IssueChild reads twice: the first resolves the binding, the
				// second decides; the narrowing lands after the second.
				store.arm(func() { store.arm(narrow) })
				_, err = svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "relay"})
			}
			if err == nil {
				t.Fatal("a capability decided under the consent the host withdrew before the mint was handed out")
			}
			_, err = svc.IssueForWorkload(h.ctx, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "relay", Organization: acme})
			code(t, err, domain.Denied)
		})
	}
}

// consented replaces an installation's consent with bindings, as a host
// that installs by consent narrows it.
func (h *harness) consented(org, target string, bindings map[string]domain.Binding) {
	h.t.Helper()
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		inst, err := tx.Installation(authority.StableInstallationID(org, target))
		if err != nil {
			return err
		}
		inst.Bindings, inst.Revision = bindings, inst.Revision+1
		return tx.PutInstallation(inst)
	}); err != nil {
		h.t.Fatal(err)
	}
}

func refusedByConsent(t *testing.T, err error) {
	t.Helper()
	code(t, err, domain.Denied)
	if !strings.Contains(err.Error(), "consents to") {
		t.Fatalf("refused for another reason than the consent: %v", err)
	}
}

// The consent bounds an installation acting for itself through its
// solution's binding, and an issue from a delegation through the module's.
func TestTheConsentBoundsInstallationAndDelegationIssues(t *testing.T) {
	t.Run("an installation acting for itself", func(t *testing.T) {
		h := newHarness(t)
		h.must(h.agent("a", "store"))
		h.consented(acme, "a", map[string]domain.Binding{"legacy": {ID: "legacy", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}})
		_, err := h.agent("a", "store")
		refusedByConsent(t, err)
	})
	t.Run("an issue from a delegation", func(t *testing.T) {
		h := newHarness(t)
		rob := h.person("rob")
		d, err := h.svc.Delegate(h.ctx, rob, "store", []*basev0.WorkScopeV1{owned(kind, "", []string{"read"}, "store-x")}, "a job")
		if err != nil {
			t.Fatal(err)
		}
		h.consented(acme, "store", map[string]domain.Binding{})
		_, err = h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "legacy"})
		refusedByConsent(t, err)
	})
}
