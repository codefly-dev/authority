package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// pageReachingTheStore is a module page whose roles reach the owner-aware
// store, the legacy store (which checks no owner) and a shared kind through
// its own bindings.
func pageReachingTheStore(t *testing.T, h *harness) {
	t.Helper()
	shared := domain.Module{Name: "profiles", Principal: "profiles", Kind: domain.KindModule, Generation: 1, OwnerAware: true,
		SharedKinds: []string{"profiles.profile"}, ResourceKinds: []*basev0.WorkScopeV1{sc("profiles.profile", "read"), sc("profiles.secret", "read")}}
	if _, err := h.svc.ApplyModule(h.ctx, shared); err != nil {
		t.Fatal(err)
	}
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{
		"store":    {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}},
		"legacy":   {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
		"profiles": {ID: "profiles", Audience: "profiles", InvokeScopes: []*basev0.WorkScopeV1{sc("profiles.profile", "read"), sc("profiles.secret", "read")}},
	}
	reach := []*basev0.WorkScopeV1{sc(kind, "read"), sc(legacyKind, "read"), sc("profiles.profile", "read"), sc("profiles.secret", "read")}
	m.Roles[domain.InstallerRole] = append([]*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(kind, "read", "write")}, reach[1:]...)
	m.Roles["viewer"] = append([]*basev0.WorkScopeV1{sc("pages.note", "read")}, reach...)
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
}

// RBAC-1: a module page's role reaches a module that checks owners only as
// the data its own installation owns, exactly as a solution's role does: the
// composition installation's principal (StablePrincipalID of the organization
// and the module) is the owner selected, whichever path issues it (the page's
// call, the page module's own hop, the resources answer). A solution's data in
// the store, or another organization's page installation's, is out of a
// module page viewer's reach; what checks no owner (the legacy store) and a
// kind its audience declares shared are unselected as before. An installation
// a host records without a principal owns nothing, so its roles carry nothing
// of an owner-aware module's kinds.
func TestRBAC1AModulePageRoleReachesAnOwnerAwareModuleAsItsInstallationsData(t *testing.T) {
	h := newHarness(t)
	pageReachingTheStore(t, h)
	mine := h.principal(acme, "pages")

	t.Run("the page's call to the owner-aware store is the page installation's data", func(t *testing.T) {
		got := h.must(h.page("maya", "pages", "store"))
		exactly(t, got, kind, mine, []string{"read"})
		if err := h.check(got); err != nil {
			t.Fatal(err)
		}
		exactly(t, h.must(h.page("maya", "pages", "store", owned(kind, mine, []string{"read"}))), kind, mine, []string{"read"})
	})
	t.Run("the page module's own hop for the person is the same", func(t *testing.T) {
		exactly(t, h.must(h.through("maya", "pages", "store")), kind, mine, []string{"read"})
	})
	t.Run("another installation's data is refused: a solution's, another organization's page", func(t *testing.T) {
		for _, other := range []string{h.principal(acme, "a"), h.principal(globex, "pages"), ""} {
			_, err := h.page("maya", "pages", "store", owned(kind, other, []string{"read"}))
			refused(t, err, `a child widens what its owner holds through binding "store"`)
		}
	})
	t.Run("the resources answer is the page installation's", func(t *testing.T) {
		got := h.must(h.page("maya", "pages", "store"))
		grants, err := h.svc.ListResources(h.ctx, got.Token, "store", kind, "read")
		if err != nil || len(grants) != 1 || !grants[0].All || grants[0].Owner != mine {
			t.Fatalf("resources %+v (%v), want every resource owned by %s alone", grants, err, mine)
		}
	})
	t.Run("a person naming the page's binding is never issued the whole kind", func(t *testing.T) {
		got, err := h.svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "pages", Binding: "store"})
		if err == nil {
			for _, s := range got.Context.GetAuthorityScopes() {
				if s.GetResourceKind() == kind && s.GetResourceOwnerId() == "" {
					t.Fatalf("naming the page's binding carries %s across every owner: %v", kind, got.Context.GetAuthorityScopes())
				}
			}
			return
		}
		refused(t, err, "pages does not declare owner-aware checking")
	})
	t.Run("the legacy store, which checks no owner, is unchanged", func(t *testing.T) {
		exactly(t, h.must(h.page("maya", "pages", "legacy-store")), legacyKind, "", []string{"read"})
	})
	t.Run("a shared kind is held unselected; an owned kind beside it is the installation's", func(t *testing.T) {
		got := h.must(h.page("maya", "pages", "profiles"))
		var shared, secret bool
		for _, s := range effective(got) {
			shared = shared || s.GetResourceKind() == "profiles.profile" && s.GetResourceOwnerId() == ""
			secret = secret || s.GetResourceKind() == "profiles.secret" && s.GetResourceOwnerId() == mine
			if s.GetResourceKind() == "profiles.secret" && s.GetResourceOwnerId() != mine {
				t.Fatalf("an owned kind beside a shared one is not the installation's: %v", effective(got))
			}
		}
		if !shared || !secret {
			t.Fatalf("effective %v", effective(got))
		}
	})
	t.Run("an installation recorded without a principal owns nothing there", func(t *testing.T) {
		inst := h.pagesAt(acme)
		inst.PrincipalID = ""
		if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
			t.Fatal(err)
		}
		_, err := h.page("maya", "pages", "store")
		refused(t, err, `holds nothing at store through binding "store"`)
		exactly(t, h.must(h.page("maya", "pages", "legacy-store")), legacyKind, "", []string{"read"})
	})
}

// RBAC-1: a composition installation recorded before module installations
// held a principal is given its principal when the module is delivered again,
// at a revision above every capability sealed to it, so a capability that
// carried the page's roles across every owner ends.
func TestRBAC1AnInstallationWithoutAPrincipalIsGivenOneAndItsOldCapabilitiesEnd(t *testing.T) {
	h := newHarness(t)
	pageReachingTheStore(t, h)
	inst := h.pagesAt(acme)
	inst.PrincipalID = ""
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
		t.Fatal(err)
	}
	old := h.must(h.page("maya", "pages", "legacy-store"))
	m := pageModule(2, true)
	stored, err := func() (domain.Module, error) {
		var out domain.Module
		return out, h.store.Read(h.ctx, func(tx authority.Tx) (err error) { out, err = tx.ModuleNamed("pages"); return err })
	}()
	if err != nil {
		t.Fatal(err)
	}
	m.Bindings, m.Roles = stored.Bindings, stored.Roles
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	now := h.pagesAt(acme)
	if now.ID != inst.ID || now.PrincipalID != h.principal(acme, "pages") || now.Revision <= inst.Revision {
		t.Fatalf("redelivery left %+v, was %+v", now, inst)
	}
	if err := h.check(old); err == nil {
		t.Fatal("a capability sealed before the installation held its principal outlived it")
	}
	exactly(t, h.must(h.page("maya", "pages", "store")), kind, now.PrincipalID, []string{"read"})
}

// RBAC-1 migration: what a module page wrote before its installation held a
// principal is unowned in the store, so owner selection hides it. The store
// attaches each such resource to the page installation through the same
// AuthorizeTransfer a solution's installation uses: a person present on the
// page, holding write there through their role and admin on the resource
// through their own organization grants. Afterwards the row is the
// installation's: its decision names the principal, and a viewer's capability
// selects exactly that owner, so the row is visible again. Nobody else's
// principal is a target, and a viewer (no write) cannot attach.
func TestRBAC1AModulePageAttachesWhatItWroteBeforeItHeldAPrincipal(t *testing.T) {
	h := newHarness(t)
	pageReachingTheStore(t, h)
	mine := h.principal(acme, "pages")
	h.grant("pages", domain.InstallerRole, "ada") // ada administers store-x through her organization role
	transfer := func(person, to string) (authority.TransferDecision, error) {
		at := h.must(h.page(person, "pages", "store"))
		return h.svc.AuthorizeTransfer(h.ctx, authority.TransferRequest{Token: at.Token, Store: authority.Workload{Module: "store"},
			Kind: kind, ResourceID: "store-x", From: acme, To: to})
	}
	if _, err := transfer("ada", h.principal(acme, "a")); err == nil {
		t.Fatal("a module page's capability attached a resource to a solution's principal")
	}
	h.grant("pages", "viewer", "rob")
	if _, err := transfer("rob", mine); err == nil {
		t.Fatal("a viewer without write on the page's data attached a resource")
	}
	d, err := transfer("ada", mine)
	if err != nil || d.PrincipalID != mine {
		t.Fatalf("attach to the page installation: %+v %v", d, err)
	}
	if got := h.pagesAt(acme).Owned[kind]; len(got) != 1 || got[0] != "store-x" {
		t.Fatalf("the installation's attachments are %v", got)
	}
	viewer := h.must(h.page("maya", "pages", "store", owned(kind, mine, []string{"read"}, "store-x")))
	exactly(t, viewer, kind, mine, []string{"read"}, "store-x")
}

// ledger is a module that checks no owner, with a binding to itself: what a
// module page's role reaches as it is (decide.ModuleRoleAt), for the tests of
// a page's binding that are not about owners.
const ledgerKind = "ledger.entry"

func applyLedger(t *testing.T, h *harness) {
	t.Helper()
	l := domain.Module{Name: "ledger", Principal: "ledger", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc(ledgerKind, "read", "write")},
		Bindings:      map[string]domain.Binding{"self": {ID: "self", Audience: "ledger", InvokeScopes: []*basev0.WorkScopeV1{sc(ledgerKind, "read", "write")}}}}
	if _, err := h.svc.ApplyModule(h.ctx, l); err != nil {
		t.Fatal(err)
	}
}

// ledgerPage is a module page whose viewer reads the ledger and whose
// installer writes it, through its binding "ledger", beside a binding to the
// owner-aware store.
func ledgerPage(t *testing.T, h *harness) {
	t.Helper()
	applyLedger(t, h)
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{
		"ledger": {ID: "ledger", Audience: "ledger", InvokeScopes: []*basev0.WorkScopeV1{sc(ledgerKind, "read", "write")}},
		"store":  {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}},
	}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(ledgerKind, "read", "write"), sc(kind, "read", "write")}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(ledgerKind, "read"), sc(kind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
}
