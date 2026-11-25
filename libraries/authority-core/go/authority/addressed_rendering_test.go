package authority_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/declare"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The desk is a solution whose roles mix every spelling of a grant: its own
// kind, a bundle the store publishes (collection:read), and scopes it spells
// out on the store's kind and the archive's. It reaches the store, the
// archive, and a vault that serves the store's kind too, over a binding whose
// ceiling is bare actions on a resource-kind slot: the sibling a scope held
// at every audience leaks to.
const deskContract = `schema: codefly/module-contract/v1
principal: desk
owner_aware: true
namespaces: []
queues: []
scope_ceilings: [{resource_kind: desk.note, actions: [read, write]}]
roles:
  - name: admin
    includes: [{module: store, bundle: browse}]
    scopes:
      - {resource_kind: desk.note, actions: [read, write]}
      - {resource_kind: collection, actions: [create, write]}
  - name: user
    includes: [{module: store, bundle: browse}]
    scopes:
      - {resource_kind: desk.note, actions: [read]}
      - {resource_kind: archive.entry, actions: [read]}
bindings:
  - id: store
    operations: [invoke]
    audience: {from: desk/store-audience}
    scope_ceiling:
      invoke: [{resource_kind: collection, actions: [create, read, write]}]
  - id: archive
    operations: [invoke]
    audience: {from: desk/archive-audience}
    scope_ceiling:
      invoke: [{resource_kind: archive.entry, actions: [read]}]
  - id: vault
    operations: [invoke]
    audience: {from: desk/vault-audience}
    resource_kind: {from: desk/vault-resource-kind}
    scope_ceiling:
      invoke: [read]
destinations: []
`

const deskStoreContract = `schema: codefly/module-contract/v1
principal: store
namespaces: []
queues: []
scope_ceilings: [{resource_kind: collection, actions: [admin, create, read, write]}]
bindings: []
destinations: []
bundles:
  - name: browse
    scopes: [{resource_kind: collection, actions: [read]}]
`

type deskBundles map[string]*modulecontract.Contract

func (b deskBundles) Bundle(module, name string) ([]modulecontract.CeilingScope, error) {
	return b[module].Bundle(name)
}

// desk is the desk at generation as a host composes it from the render of
// its contract (declare.Module, delivered.Declared). literal is the render
// before a grant on another module's kind was addressed: every audience
// grant carried in the role's scopes instead, held at every audience.
func desk(t *testing.T, generation uint64, literal bool) domain.Module {
	t.Helper()
	parse := func(text string) *modulecontract.Contract {
		contract, err := modulecontract.Parse([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return contract
	}
	infos := []*basev0.ConfigurationInformation{{Name: "desk", ConfigurationValues: []*basev0.ConfigurationValue{
		{Key: "store-audience", Value: "store"}, {Key: "archive-audience", Value: "archive"},
		{Key: "vault-audience", Value: "vault"}, {Key: "vault-resource-kind", Value: kind},
	}}}
	resolve := func(contract *modulecontract.Contract) (*modulecontract.Resolved, error) {
		return contract.Resolve(solutionhost.ConfigurationValues(infos), modulecontract.WithBundles(deskBundles{"store": parse(deskStoreContract)}))
	}
	declaration, _, err := declare.Module(t.TempDir(), "desk", parse(deskContract), resolve)
	if err != nil {
		t.Fatal(err)
	}
	if literal {
		for i, role := range declaration.Document.Roles {
			for _, entry := range role.Audiences {
				declaration.Document.Roles[i].Scopes = append(declaration.Document.Roles[i].Scopes, entry.Scopes...)
			}
			declaration.Document.Roles[i].Audiences = nil
		}
	}
	m, err := delivered.Declared(&solutionhost.ModuleManifest{Alias: "desk", Kind: solutionhost.Kind(domain.KindSolution), Generation: generation}, declaration, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// deskHarness composes the desk's callees (the harness's store, an archive
// and a vault serving the store's kind), delivers the desk and installs it
// with maya its user and remi its admin.
func deskHarness(t *testing.T, literal bool) *harness {
	t.Helper()
	h := newHarness(t)
	for _, m := range []domain.Module{
		{Name: "archive", Principal: "archive", Kind: domain.KindModule, Generation: 1, OwnerAware: true, ResourceKinds: []*basev0.WorkScopeV1{sc("archive.entry", "read")}},
		{Name: "vault", Principal: "vault", Kind: domain.KindModule, Generation: 1, OwnerAware: true, ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "read")}},
		desk(t, 1, literal),
	} {
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	h.install(acme, "desk")
	h.grant("desk", "user", "maya")
	h.grant("desk", "admin", "remi")
	return h
}

// The render addresses every grant on another module's kind, so the desk's
// roles hold literally only the desk's own kind.
func TestTheRenderedDeskHoldsLiterallyOnlyItsOwnKind(t *testing.T) {
	t.Parallel()
	m := desk(t, 1, false)
	for role, want := range map[string]string{domain.AdminRole: "desk.note:read+write", domain.UserRole: "desk.note:read"} {
		if got := scopeText(m.Roles[role]); got != want {
			t.Fatalf("%s holds literally %s, want %s", role, got, want)
		}
	}
	if got := scopeText(m.AudienceRoles[domain.AdminRole]["store"]); got != "collection:create+read+write" {
		t.Fatalf("admin at the store: %s", got)
	}
	if got := scopeText(m.AudienceRoles[domain.UserRole]["store"]) + " / " + scopeText(m.AudienceRoles[domain.UserRole]["archive"]); got != "collection:read / archive.entry:read" {
		t.Fatalf("user at the store / the archive: %s", got)
	}
	if len(m.AudienceRoles[domain.AdminRole]) != 1 || len(m.AudienceRoles[domain.UserRole]) != 2 {
		t.Fatalf("a role is addressed somewhere it names nothing: %+v", m.AudienceRoles)
	}
	if err := decide.ValidateModule(m); err != nil {
		t.Fatal(err)
	}
}

// A role whose every grant on another module's kind is addressed still
// reaches each callee through each binding, however the call is made: a root
// naming the binding and the desk's hop, the desk's page, the desk's backend
// relaying a person's capability, and the installation acting for itself.
func TestAnAddressedRoleReachesEachCalleeThroughEachBinding(t *testing.T) {
	t.Parallel()
	h := deskHarness(t, false)
	owner := h.principal(acme, "desk")
	t.Run("a root naming the binding, then the hop", func(t *testing.T) {
		exactly(t, h.must(h.addressed("maya", "desk", "store")), kind, owner, []string{"read"})
		exactly(t, h.must(h.addressed("maya", "desk", "archive")), "archive.entry", owner, []string{"read"})
		exactly(t, h.must(h.addressed("remi", "desk", "store")), kind, owner, []string{"create", "read", "write"})
		// The literal scope and the bundle's are one grant at the store: the
		// admin's write is reachable, asked alone or with the bundle's read.
		exactly(t, h.must(h.addressed("remi", "desk", "store", owned(kind, owner, []string{"write"}))), kind, owner, []string{"write"})
	})
	t.Run("the page", func(t *testing.T) {
		exactly(t, h.must(h.page("maya", "desk", "store")), kind, owner, []string{"read"})
		exactly(t, h.must(h.page("maya", "desk", "archive")), "archive.entry", owner, []string{"read"})
		exactly(t, h.must(h.page("remi", "desk", "store")), kind, owner, []string{"create", "read", "write"})
		exactly(t, h.must(h.page("remi", "desk", "store", owned(kind, owner, []string{"create", "write"}))), kind, owner, []string{"create", "write"})
	})
	t.Run("the backend relaying a capability addressed to the desk", func(t *testing.T) {
		exactly(t, h.must(h.through("maya", "desk", "store")), kind, owner, []string{"read"})
		exactly(t, h.must(h.through("maya", "desk", "archive")), "archive.entry", owner, []string{"read"})
		exactly(t, h.must(h.through("remi", "desk", "store")), kind, owner, []string{"create", "read", "write"})
		// One capability at the desk reaches both callees, one hop each.
		root := h.must(h.root("maya", "desk"))
		for binding, want := range map[string]string{"store": kind, "archive": "archive.entry"} {
			child, err := h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "desk"}, authority.IssueRequest{Binding: binding})
			exactly(t, h.must(child, err), want, owner, []string{"read"})
		}
	})
	t.Run("the installation acting for itself", func(t *testing.T) {
		agent, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "desk"}, h.inst(acme, "desk").ID, authority.IssueRequest{Audience: "store", Binding: "store"})
		exactly(t, h.must(agent, err), kind, owner, []string{"create", "read", "write"})
	})
}

// The same role is refused at a sibling serving the same kind, which the
// desk's own binding there would carry, and holds nothing of a callee's kind
// on a capability addressed to the desk itself. Rendered as it was before
// (the grant in the role's scopes), each of those was issued.
func TestAnAddressedRoleIsRefusedAtASiblingAndAtTheUnitItself(t *testing.T) {
	t.Parallel()
	sibling := func(h *harness, person string) map[string]func() (authority.Issued, error) {
		return map[string]func() (authority.Issued, error){
			"a root naming the binding, then the hop": func() (authority.Issued, error) { return h.addressed(person, "desk", "vault") },
			"the page":          func() (authority.Issued, error) { return h.page(person, "desk", "vault") },
			"the backend relay": func() (authority.Issued, error) { return h.through(person, "desk", "vault") },
			"the installation acting for itself": func() (authority.Issued, error) {
				return h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "desk"}, h.inst(acme, "desk").ID, authority.IssueRequest{Audience: "vault", Binding: "vault"})
			},
		}
	}
	t.Run("rendered literally, the grant was held at the sibling and at the desk", func(t *testing.T) {
		h := deskHarness(t, true)
		for name, ask := range sibling(h, "maya") {
			got, err := ask()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			exactly(t, got, kind, h.principal(acme, "desk"), []string{"read"})
		}
		named, err := h.svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "desk", Binding: "store"})
		if !scope.HoldsAction(effective(h.must(named, err)), kind, "read") {
			t.Fatalf("the literal render's root naming the store binding carried nothing of the store's kind: %s", scopeText(effective(named)))
		}
	})
	t.Run("addressed, it is refused at both", func(t *testing.T) {
		h := deskHarness(t, false)
		for _, person := range []string{"maya", "remi"} {
			for name, ask := range sibling(h, person) {
				if got, err := ask(); err == nil {
					t.Fatalf("%s: %s holds %s at the vault, a sibling the grant is not addressed to", name, person, scopeText(effective(got)))
				}
			}
			// Addressed to the desk itself: its own kind and nothing else,
			// whether or not the ask names a binding.
			for _, binding := range []string{"", "store"} {
				root, err := h.svc.IssueForPerson(h.ctx, h.person(person), authority.IssueRequest{Audience: "desk", Binding: binding})
				for _, held := range effective(h.must(root, err)) {
					if held.GetResourceKind() != "desk.note" && len(held.GetActions()) > 0 {
						t.Fatalf("%s's capability addressed to the desk (binding %q) carries %s", person, binding, scopeText(effective(root)))
					}
				}
			}
			for _, binding := range []string{"", "store", "vault"} {
				if got, err := h.svc.IssueForPerson(h.ctx, h.person(person), authority.IssueRequest{Audience: "desk", Binding: binding,
					Scopes: []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "desk"), []string{"read"})}}); err == nil {
					t.Fatalf("%s asked the store's kind on a capability addressed to the desk (binding %q) and got %s", person, binding, scopeText(effective(got)))
				}
			}
			// A root naming the binding to the sibling holds nothing under it.
			_, err := h.svc.IssueForPerson(h.ctx, h.person(person), authority.IssueRequest{Audience: "desk", Binding: "vault"})
			refused(t, err, `holds nothing under operation binding "vault"`)
		}
		// The archive's kind is the user's alone, and only at the archive.
		if got, err := h.addressed("remi", "desk", "archive"); err == nil {
			t.Fatalf("the admin holds %s at the archive, which only the user is granted", scopeText(effective(got)))
		}
		// A person's own session at a callee holds nothing: the role is on
		// the desk's installation, not the callee's.
		if got, err := h.root("maya", "store"); err == nil {
			t.Fatalf("maya's own session at the store holds %s", scopeText(effective(got)))
		}
	})
}

// An installation consented on the literal render that receives the addressed
// one re-converges without a click: nothing new is asked (decide.Widens), the
// consent moves to the new generation, what was issued under the literal one
// ends, and its holders keep each callee and lose the sibling. The reverse
// (a producer still rendering literally redelivers after the addressed
// render was approved) asks for consent, and the addressed role is held
// meanwhile. Both hold for a consent recorded before reach was kept.
func TestAnInstallationConsentedOnTheLiteralRenderReconvergesOnTheAddressedOne(t *testing.T) {
	t.Parallel()
	for _, legacy := range []bool{false, true} {
		name := "a consent that kept its reach"
		if legacy {
			name = "a consent recorded before reach was kept"
		}
		t.Run(name, func(t *testing.T) {
			h := deskHarness(t, true)
			svc, events := journaled(h)
			forgetReach := func() {
				if !legacy {
					return
				}
				if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
					inst, err := tx.Installation(h.inst(acme, "desk").ID)
					if err != nil {
						return err
					}
					inst.Consent.ReachDigest, inst.Consent.Reach = "", ""
					return tx.PutInstallation(inst)
				}); err != nil {
					t.Fatal(err)
				}
			}
			forgetReach()
			owner := h.principal(acme, "desk")
			before := h.stored(acme, "desk")
			old := map[string]authority.Issued{
				"the store":   h.must(h.addressed("maya", "desk", "store")),
				"the sibling": h.must(h.addressed("maya", "desk", "vault")),
				"the desk":    h.must(h.root("remi", "desk")),
			}

			addressed := desk(t, 2, false)
			if asks := decide.Widens(desk(t, 1, true), addressed); len(asks) > 0 {
				t.Fatalf("the addressed render asks more than the literal one approved: %v", asks)
			}
			if !decide.Narrowed(desk(t, 1, true), addressed) {
				t.Fatal("the addressed render does not narrow the literal one, so what was issued would stand")
			}
			if _, err := svc.ApplyModule(h.ctx, addressed); err != nil {
				t.Fatal(err)
			}
			after := h.stored(acme, "desk")
			if e, ok := lastEvent(*events, domain.InstallationUpgradeAvailable); ok {
				t.Fatalf("the addressed render asked for consent: %+v", e)
			}
			if after.Status != domain.Active || after.Consent.Generation != 2 || after.Revision != before.Revision+1 || decide.UpgradeAvailable(after, addressed) {
				t.Fatalf("the installation did not re-converge: %+v, was %+v", after, before)
			}
			for where, capability := range old {
				if err := h.check(capability); err == nil {
					t.Fatalf("a capability issued at %s under the literal render still checks", where)
				}
			}
			// Every grant is kept, at its callee; the sibling is gone.
			if grants := h.roleGrants("desk"); len(grants) < 2 {
				t.Fatalf("the re-convergence dropped role grants: %+v", grants)
			}
			exactly(t, h.must(h.addressed("maya", "desk", "store")), kind, owner, []string{"read"})
			exactly(t, h.must(h.page("maya", "desk", "archive")), "archive.entry", owner, []string{"read"})
			exactly(t, h.must(h.through("remi", "desk", "store")), kind, owner, []string{"create", "read", "write"})
			if got, err := h.addressed("maya", "desk", "vault"); err == nil {
				t.Fatalf("the sibling is still reached after the re-convergence: %s", scopeText(effective(got)))
			}

			// The reverse: the literal render again, after the addressed one.
			forgetReach()
			converged := h.stored(acme, "desk")
			literal := desk(t, 3, true)
			if _, err := svc.ApplyModule(h.ctx, literal); err != nil {
				t.Fatal(err)
			}
			held := h.stored(acme, "desk")
			// The consent stands on the addressed generation. (The revision
			// moves: read as declared, the literal render drops every
			// audience grant, which narrows, so what was issued ends.)
			if held.Status != domain.Active || held.Consent.Generation != 2 || held.Consent.Digest != converged.Consent.Digest {
				t.Fatalf("the literal render moved the consent of an installation consented on the addressed one: %+v, was %+v", held, converged)
			}
			if !decide.UpgradeAvailable(held, literal) {
				t.Fatal("the literal render does not offer the upgrade")
			}
			e, ok := lastEvent(*events, domain.InstallationUpgradeAvailable)
			if !ok || e.Subject != held.ID || !strings.Contains(e.Detail["widened"], "role admin reaches further") || !strings.Contains(e.Detail["widened"], "role user reaches further") {
				t.Fatalf("installation.upgrade_available does not name the roles reaching further: %+v %v", e, ok)
			}
			if got, err := h.addressed("maya", "desk", "vault"); err == nil {
				t.Fatalf("the literal grant is held before its upgrade is approved: %s", scopeText(effective(got)))
			}
			exactly(t, h.must(h.addressed("maya", "desk", "store")), kind, owner, []string{"read"})
		})
	}
}

// What an administrator reviews of an addressed role: its scopes are those
// held at every audience (the desk's own kind), and each grant addressed to a
// callee is the role's reach row at that callee, with the binding's path, the
// scopes and the operations. The sibling has no row.
func TestTheReviewedOfferShowsAnAddressedGrantAsTheRolesReachAtItsCallee(t *testing.T) {
	t.Parallel()
	h := deskHarness(t, false)
	offer, err := h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "desk")
	if err != nil {
		t.Fatal(err)
	}
	row := func(role, module string) (domain.ReachRow, bool) {
		i := slices.IndexFunc(offer.Reach[role], func(r domain.ReachRow) bool { return r.Module == module && r.Via == decide.ReachBinding })
		if i < 0 {
			return domain.ReachRow{}, false
		}
		return offer.Reach[role][i], true
	}
	for _, want := range []struct{ role, module, scopes string }{
		{domain.AdminRole, "store", "collection:create+read+write"},
		{domain.UserRole, "store", "collection:read"},
		{domain.UserRole, "archive", "archive.entry:read"},
	} {
		got, ok := row(want.role, want.module)
		if !ok || scopeText(got.Scopes) != want.scopes || strings.Join(got.Path, ">") != "desk>"+want.module {
			t.Fatalf("%s at %s: %+v (%v), want %s", want.role, want.module, got, ok, want.scopes)
		}
	}
	for _, role := range []string{domain.AdminRole, domain.UserRole} {
		if got, ok := row(role, "vault"); ok {
			t.Fatalf("%s is shown a reach at the vault: %+v", role, got)
		}
		if scope.HoldsAction(offer.Module.Roles[role], kind, "read") {
			t.Fatalf("%s's reviewed scopes still hold the store's kind at every audience: %s", role, scopeText(offer.Module.Roles[role]))
		}
	}
	if _, ok := row(domain.AdminRole, "archive"); ok {
		t.Fatal("the admin is shown a reach at the archive, which only the user is granted")
	}
}
