package authority_test

import (
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// Organisation roles decide administration only. A person reaches a module
// only through a role (admin, user) on an installation: a solution's, or a
// module page's. Whatever an organisation role is called, a person holding
// one and no role on any installation is refused at every module, page or no
// page, owner-aware or not, shared kind or not; the same person is admitted
// once they hold a role on an installation that reaches the module, and
// through that installation's binding alone.
func TestAnOrganisationRoleReachesNoModule(t *testing.T) {
	h := matrixHarness(t)
	// alex is the organisation's administrator; boss holds an organisation
	// role named for nothing the core knows; rob holds organisation roles
	// named after modules' kinds. None holds a role on an installation.
	for _, person := range []string{"alex", "boss", "rob"} {
		for audience, reason := range map[string]string{
			"legacy-store":    "legacy-store declares no roles",
			"ledger":          "ledger declares no roles",
			"store":           "store declares no roles",
			"profiles":        "profiles declares no roles",
			"store-elsewhere": "store-elsewhere declares no roles",
			"pages":           person + " holds no role on pages",
			"a":               person + " holds no role on a",
		} {
			_, err := h.root(person, audience)
			refused(t, err, reason)
			code(t, err, domain.Denied)
		}
		// Through a page they hold no role on, at a module it binds and at
		// one it does not.
		_, err := h.page(person, "pages", "store")
		refused(t, err, person+" holds no role on pages")
		_, err = h.page(person, "pages", "store-elsewhere")
		refused(t, err, "pages declares no binding to store-elsewhere")
		// Through a solution they hold no role on.
		_, err = h.through(person, "a", "store")
		refused(t, err, person+" holds no role on a")
	}

	// Administration is the organisation role's, and is untouched: alex, who
	// reaches no module, seats boss on the solution.
	h.grant("a", domain.UserRole, "boss")
	// boss now reaches the store through the solution's binding, as its user,
	// and still holds nothing there on their own session.
	exactly(t, h.must(h.through("boss", "a", "store")), kind, h.principal(acme, "a"), []string{"read"})
	_, err := h.root("boss", "store")
	refused(t, err, "store declares no roles")
	// alex seated nobody but boss: alex is still refused.
	_, err = h.through("alex", "a", "store")
	refused(t, err, "alex holds no role on a")
}

// A capability owned by a person, addressed to a module that declares no
// roles and naming no installation it came through, is one no issuance makes.
// One minted elsewhere (another host, an earlier version) is refused when it
// is checked, with or without a method, and answers no resource.
func TestACapabilityOnAPersonsOwnSessionIsRefusedAtAModuleWithNoRoles(t *testing.T) {
	h := newHarness(t)
	const method = "/legacy.v1.Store/Read"
	var legacy domain.Module
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) { legacy, err = tx.ModuleNamed("legacy-store"); return err }); err != nil {
		t.Fatal(err)
	}
	legacy.Generation++
	legacy.Methods = map[string]domain.MethodPolicy{method: {Requires: []*basev0.WorkScopeV1{sc(legacyKind, "read")}}}
	if _, err := h.svc.ApplyModule(h.ctx, legacy); err != nil {
		t.Fatal(err)
	}
	pageReachingTheStore(t, h) // maya is the page's user
	minter := workcontext.Authority{Issuer: h.cfg.Issuer, KeyID: h.cfg.KeyID, Signer: h.cfg.Signer, Seals: h.svc.Seals(), Revisions: h.svc.Revisions(), Now: h.cfg.Clock}
	for _, person := range []string{"alex", "rob", "maya"} {
		token, _, err := minter.Start(h.ctx, workcontext.StartInput{TenantID: acme, OrganizationID: acme, OwnerPrincipalID: person, OwnerPrincipalKind: "human",
			TaskID: "own-session-" + person, SessionID: "session-" + person, Audience: "legacy-store", AuthorityScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")},
			InstallationID: h.inst(acme, "legacy-store").ID, TTL: time.Minute, ReplayPolicy: workcontext.ReplayIdempotent})
		if err != nil {
			t.Fatal(err)
		}
		const reason = "legacy-store declares no roles"
		_, _, err = h.svc.Check(h.ctx, token, "legacy-store")
		refused(t, err, reason)
		_, _, _, err = h.svc.CheckMethod(h.ctx, token, "legacy-store", method, false)
		refused(t, err, reason)
		_, _, _, err = h.svc.CheckMethod(h.ctx, token, "legacy-store", method, true)
		refused(t, err, reason)
		_, err = h.svc.ListResources(h.ctx, token, "legacy-store", legacyKind, "read")
		refused(t, err, reason)
	}
	// Nor does a hop from such a capability hold anything: the ledger, which
	// declares no roles, hops nobody's own session on to the legacy store.
	token, _, err := minter.Start(h.ctx, workcontext.StartInput{TenantID: acme, OrganizationID: acme, OwnerPrincipalID: "alex", OwnerPrincipalKind: "human",
		TaskID: "own-session-hop", SessionID: "session-alex", Audience: "ledger", AuthorityScopes: []*basev0.WorkScopeV1{sc(ledgerKind, "read"), sc(legacyKind, "read")},
		InstallationID: h.inst(acme, "ledger").ID, TTL: time.Minute, ReplayPolicy: workcontext.ReplayIdempotent})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.IssueChild(h.ctx, token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "legacy"})
	refused(t, err, "ledger declares no roles")
	// The same method, reached through an installation whose role the person
	// holds, is admitted: the page's user through the page's binding.
	got := h.must(h.page("maya", "pages", "legacy-store"))
	if _, _, refusal, err := h.svc.CheckMethod(h.ctx, got.Token, "legacy-store", method, false); err != nil || refusal != nil {
		t.Fatalf("the page's user is refused at the module the page binds: %v %v", refusal, err)
	}
}
