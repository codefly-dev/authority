package authority_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// hostInstalled is a core whose host decides which organizations hold each
// module (Config.HostInstallsModules): its store answers the host's own
// records, which a test writes as the host would.
type hostInstalled struct {
	*harness
	svc   *authority.Service
	store *memstore.Store
}

func newHostInstalled(t *testing.T) *hostInstalled {
	t.Helper()
	h := newHarness(t)
	cfg := h.cfg
	cfg.HostInstallsModules = true
	store := memstore.New()
	svc, err := authority.New(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{acme, globex} {
		store.PutOrganization(domain.Organization{ID: org, Name: org})
	}
	store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "admin"})
	store.PutPerson(domain.Person{ID: "alex", Organization: acme, Roles: []string{"admin"}})
	if _, err := svc.ApplyModule(h.ctx, domain.Module{Name: "relay", Principal: "relay", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyModule(h.ctx, domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read", "write")},
		Bindings: map[string]domain.Binding{
			"self": {ID: "self", Audience: "store",
				InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read")}},
			"relay": {ID: "relay", Audience: "relay", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return &hostInstalled{harness: h, svc: svc, store: store}
}

// record writes the host's own installation record of the store module.
func (h *hostInstalled) record(org, id string, status domain.Status, revision uint64) {
	h.t.Helper()
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		return tx.PutInstallation(domain.Installation{ID: id, Organization: org, Target: "store", Status: status, Revision: revision})
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hostInstalled) issue(w authority.Workload, org string) (authority.Issued, error) {
	return h.svc.IssueForWorkload(h.ctx, w, authority.IssueRequest{Binding: "self", Organization: org})
}

func (h *hostInstalled) installations() []domain.Installation {
	h.t.Helper()
	var all []domain.Installation
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
		var err error
		all, err = tx.Installations("")
		return err
	}); err != nil {
		h.t.Fatal(err)
	}
	return all
}

// The core installs no module by itself: not at delivery, not for a new
// organization, not when reconciling; and the host's record is never retired
// by the core, by withdrawal or by host setup.
func TestAHostThatInstallsModulesIsTheOnlyOneThatDoes(t *testing.T) {
	h := newHostInstalled(t)
	if all := h.installations(); len(all) != 0 {
		t.Fatalf("delivery installed %v", all)
	}
	ids, err := h.svc.OrganizationAdded(h.ctx, acme)
	if err != nil || len(ids) != 0 {
		t.Fatalf("a new organization was given %v (%v)", ids, err)
	}
	if err := h.svc.ReconcileOrganizations(h.ctx); err != nil {
		t.Fatal(err)
	}
	if all := h.installations(); len(all) != 0 {
		t.Fatalf("reconciling installed %v", all)
	}
	_, err = h.svc.OrganizationAdded(h.ctx, "nobody")
	code(t, err, domain.NotFound)

	h.record(acme, "host-1", domain.Active, 1)
	// A redelivery that narrows the module raises the host's record's
	// revision, so what was issued under the wider module ends.
	if _, err := h.svc.ApplyModule(h.ctx, domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 2,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read")},
		Bindings: map[string]domain.Binding{"self": {ID: "self", Audience: "store",
			InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read")}, HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read")}}},
	}); err != nil {
		t.Fatal(err)
	}
	if all := h.installations(); len(all) != 1 || all[0].Revision != 2 || all[0].Status != domain.Active {
		t.Fatalf("a narrowing left the host's record at %v", all)
	}
	err = h.svc.UninstallAsHost(h.ctx, acme, "host-1")
	code(t, err, domain.Denied)
	if err := h.svc.WithdrawModule(h.ctx, "store"); err != nil {
		t.Fatal(err)
	}
	all := h.installations()
	if len(all) != 1 || all[0].Status != domain.Active || all[0].Revision != 2 {
		t.Fatalf("the host's record moved: %v", all)
	}
}

// A workload is issued only where its host recorded an installation, never
// past the organization its credential is bound to, and nothing once the host
// retires the installation: its capabilities fail their next check.
func TestAWorkloadIsIssuedOnlyWhereItsHostInstalledIt(t *testing.T) {
	store := authority.Workload{Module: "store"}
	for _, tc := range []struct {
		name   string
		setup  func(h *hostInstalled)
		w      authority.Workload
		org    string
		want   domain.Code
		issued bool
	}{
		{name: "no installation anywhere", w: store, org: acme, want: domain.Precondition},
		{name: "no installation and no organization named", w: store, want: domain.Denied},
		{name: "installed elsewhere", setup: func(h *hostInstalled) { h.record(globex, "host-g", domain.Active, 1) }, w: store, org: acme, want: domain.Precondition},
		{name: "installed here", setup: func(h *hostInstalled) { h.record(acme, "host-1", domain.Active, 1) }, w: store, org: acme, issued: true},
		{name: "the only installation, no organization named", setup: func(h *hostInstalled) { h.record(acme, "host-1", domain.Active, 1) }, w: store, issued: true},
		{name: "retired by the host", setup: func(h *hostInstalled) { h.record(acme, "host-1", domain.Revoked, 2) }, w: store, org: acme, want: domain.Precondition},
		{name: "bound to another organization", setup: func(h *hostInstalled) { h.record(acme, "host-1", domain.Active, 1) },
			w: authority.Workload{Module: "store", Organization: globex}, org: acme, want: domain.Denied},
		{name: "bound here, organization implied", setup: func(h *hostInstalled) { h.record(acme, "host-1", domain.Active, 1) },
			w: authority.Workload{Module: "store", Organization: acme}, issued: true},
		{name: "bound to an organization that has no installation", setup: func(h *hostInstalled) { h.record(acme, "host-1", domain.Active, 1) },
			w: authority.Workload{Module: "store", Organization: globex}, want: domain.Precondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostInstalled(t)
			if tc.setup != nil {
				tc.setup(h)
			}
			issued, err := h.issue(tc.w, tc.org)
			if !tc.issued {
				code(t, err, tc.want)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := issued.Context.GetTenantId(); got != acme {
				t.Fatalf("issued at %q", got)
			}
			if _, _, err := h.svc.Check(h.ctx, issued.Token, "store"); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("a capability ends when the host retires the installation, and stays ended after a reinstall", func(t *testing.T) {
		h := newHostInstalled(t)
		h.record(acme, "host-1", domain.Active, 1)
		issued, err := h.issue(store, acme)
		if err != nil {
			t.Fatal(err)
		}
		h.record(acme, "host-1", domain.Revoked, 2)
		if _, _, err := h.svc.Check(h.ctx, issued.Token, "store"); err == nil {
			t.Fatal("a capability survived its installation's retirement")
		}
		h.record(acme, "host-2", domain.Active, 1)
		if _, _, err := h.svc.Check(h.ctx, issued.Token, "store"); err == nil {
			t.Fatal("a reinstall revived a capability sealed to the retired installation")
		}
		if _, err := h.issue(store, acme); err != nil {
			t.Fatal(err)
		}
	})
}

// recordConsent writes the host's installation record of the store module
// with the bindings its consent allows.
func (h *hostInstalled) recordConsent(org, id string, bindings map[string]domain.Binding) {
	h.t.Helper()
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		return tx.PutInstallation(domain.Installation{ID: id, Organization: org, Target: "store", Status: domain.Active, Revision: 1, Bindings: bindings})
	}); err != nil {
		h.t.Fatal(err)
	}
}

// What a host's consent allows of a module's bindings at one installation
// bounds every issue through them, whatever the delivery declares: a binding
// the consent does not name issues nothing, one it narrows issues within the
// narrowing, and a redelivery that widens the binding issues no more than was
// consented.
func TestAnInstallationsConsentBoundsItsModulesBindings(t *testing.T) {
	read, readWrite := []*basev0.WorkScopeV1{sc(kind, "read")}, []*basev0.WorkScopeV1{sc(kind, "read", "write")}
	for _, tc := range []struct {
		name     string
		consent  map[string]domain.Binding
		widen    bool
		want     []string
		refusal  domain.Code
		refusedB bool
	}{
		{name: "no ceiling: as delivered", want: []string{"read"}},
		{name: "the binding consented as delivered", consent: map[string]domain.Binding{"self": {ID: "self", HeadlessScopes: read, InvokeScopes: readWrite}}, want: []string{"read"}},
		{name: "a consent naming no binding", consent: map[string]domain.Binding{}, refusedB: true, refusal: domain.Denied},
		{name: "a consent naming another binding", consent: map[string]domain.Binding{"other": {ID: "other", HeadlessScopes: read}}, refusedB: true, refusal: domain.Denied},
		{name: "a widening redelivery stays within the consent", consent: map[string]domain.Binding{"self": {ID: "self", HeadlessScopes: read}}, widen: true, want: []string{"read"}},
		{name: "a widening redelivery with no ceiling widens", widen: true, want: []string{"read", "write"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostInstalled(t)
			h.recordConsent(acme, "host-1", tc.consent)
			if tc.widen {
				if _, err := h.svc.ApplyModule(h.ctx, domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 2,
					ResourceKinds: readWrite,
					Bindings:      map[string]domain.Binding{"self": {ID: "self", Audience: "store", InvokeScopes: readWrite, HeadlessScopes: readWrite}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			issued, err := h.issue(authority.Workload{Module: "store"}, acme)
			if tc.refusedB {
				code(t, err, tc.refusal)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := effective(issued)
			if len(got) != 1 || got[0].GetResourceKind() != kind || !sameActions(got[0].GetActions(), tc.want) {
				t.Fatalf("issued %v, want %s %v", got, kind, tc.want)
			}
		})
	}

	t.Run("a hop back to the module's own audience is bounded by its parent, not by the consent", func(t *testing.T) {
		h := newHostInstalled(t)
		h.recordConsent(acme, "host-1", map[string]domain.Binding{})
		h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "reader", Scopes: []domain.RoleScope{{Kind: kind, Actions: []string{"read"}}}})
		h.store.PutPerson(domain.Person{ID: "alex", Organization: acme, Roles: []string{"admin", "reader"}})
		parent, err := h.svc.IssueForPerson(h.ctx, authority.Person{ID: "alex", Organization: acme, SessionID: "s"}, authority.IssueRequest{Audience: "store"})
		if err != nil {
			t.Fatal(err)
		}
		child, err := h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self"})
		if err != nil {
			t.Fatal(err)
		}
		if got := effective(child); len(got) != 1 || !sameActions(got[0].GetActions(), []string{"read"}) {
			t.Fatalf("a hop to itself issued %v, want read", got)
		}
	})

	t.Run("a person's hop through a binding the consent does not name is refused", func(t *testing.T) {
		h := newHostInstalled(t)
		h.recordConsent(acme, "host-1", map[string]domain.Binding{})
		h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "reader", Scopes: []domain.RoleScope{{Kind: kind, Actions: []string{"read"}}}})
		h.store.PutPerson(domain.Person{ID: "alex", Organization: acme, Roles: []string{"admin", "reader"}})
		parent, err := h.svc.IssueForPerson(h.ctx, authority.Person{ID: "alex", Organization: acme, SessionID: "s"}, authority.IssueRequest{Audience: "store"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "relay"})
		code(t, err, domain.Denied)
		if !strings.Contains(err.Error(), "consents to") {
			t.Fatalf("refused for another reason: %v", err)
		}
	})
}

func sameActions(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, a := range got {
		seen[a] = true
	}
	for _, a := range want {
		if !seen[a] {
			return false
		}
	}
	return true
}
