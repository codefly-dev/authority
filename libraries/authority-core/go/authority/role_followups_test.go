package authority_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// at is solution name redelivered at generation, with the roles given.
func at(name string, generation uint64, roles map[string][]*basev0.WorkScopeV1) domain.Module {
	m := solution(name, true)
	m.Generation, m.Roles = generation, roles
	return m
}

func (h *harness) roleGrants(target string) []domain.RoleGrant {
	h.t.Helper()
	grants, err := h.svc.ListRoleGrants(h.ctx, h.admin(acme), acme, h.inst(acme, target).ID)
	if err != nil {
		h.t.Fatal(err)
	}
	return grants
}

// A redelivery that drops a role drops its grants with it, journaled as
// revoked by the delivery: a later generation declaring the name again,
// wider, finds no holder, and nobody holds a role an administrator never
// granted under that meaning. A solution always declares its two roles, so
// the target that drops them is a module page, which stops declaring roles
// and declares them again.
func TestARedeliveryDroppingARoleDropsItsGrants(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	svc, events := journaled(h)
	if _, err := svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "user", "maya")
	h.grantTeam("pages", "user", "team")
	h.grant("pages", "admin", "remi")
	for _, person := range []string{"maya", "tam"} {
		exactly(t, h.must(h.root(person, "pages")), "pages.note", "", []string{"read"})
	}

	if _, err := svc.ApplyModule(h.ctx, pageModule(2, false)); err != nil {
		t.Fatal(err)
	}
	if grants := h.roleGrants("pages"); len(grants) != 0 {
		t.Fatalf("a module page's dropped roles kept their grants: %v", grants)
	}
	if n := countEvents(*events, domain.RoleRevoked); n != 3 {
		t.Fatalf("%d revocations journaled, want one for each of the three dropped grants", n)
	}
	if e, ok := lastEvent(*events, domain.RoleRevoked); !ok || e.Actor != "delivery:pages" {
		t.Fatalf("the dropped role's grant was not journaled as revoked by the delivery: %+v %v", e, ok)
	}

	// Declared again, and wider: the old holders hold nothing, before the
	// upgrade is approved and after it, until granted.
	wider := pageModule(3, true)
	wider.Roles["user"] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	if _, err := svc.ApplyModule(h.ctx, wider); err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"maya", "tam", "remi"} {
		_, err := h.root(person, "pages")
		refused(t, err, "holds no role")
	}
	if _, err := h.approvePage(svc, "alex"); err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"maya", "tam", "remi"} {
		_, err := h.root(person, "pages")
		refused(t, err, "holds no role")
	}
	if grants := h.roleGrants("pages"); len(grants) != 0 {
		t.Fatalf("declaring the roles again revived grants: %v", grants)
	}
	h.grant("pages", "user", "maya")
	exactly(t, h.must(h.root("maya", "pages")), "pages.note", "", []string{"read", "write"})
}

// A module page's role reaches through the page's bindings as a solution's
// does: it may name what a binding consumes, and, declared through that
// binding, what the modules it reaches consume onward (the store's own
// binding carries the kind's write); never what nothing reaches, nor a kind
// reached downstream it does not declare through its binding.
func TestAModulePageRoleNamesWhatItServesOrConsumes(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read")}}}
	m.Roles["user"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatalf("a page role naming what its binding consumes is accepted: %v", err)
	}
	m.Generation = 2
	m.Roles["user"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read", "write")}
	_, err := h.svc.ApplyModule(h.ctx, m)
	refused(t, err, "grants beyond what pages serves or explicitly consumes")
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"user": {"store": {sc(kind, "write")}}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatalf("the store's own binding reaches the kind's write, so a role may name it through the binding: %v", err)
	}
	m.Generation = 3
	m.Roles["user"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read"), sc("unreached.kind", "read")}
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"user": {"store": {sc("unreached.kind", "read")}}}
	_, err = h.svc.ApplyModule(h.ctx, m)
	refused(t, err, `names unreached.kind:read through binding "store", which reaches it nowhere`)
}

// A person holding only a module page's role is issued, through the page's
// binding, a child narrowed to the role intersected with the binding, and
// nothing beyond: not an action the binding does not carry, not an action the
// role does not grant, not without the role, and not on their own session at
// the module the page reaches, which holds nothing there. At a
// module that checks owners the role reaches only the page installation's
// own data (RBAC-1).
func TestAModulePageRoleReachesThroughThePagesBinding(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ledgerPage(t, h)
	h.grant("pages", "user", "maya")

	child := h.must(h.through("maya", "pages", "ledger"))
	exactly(t, child, ledgerKind, "", []string{"read"})
	if err := h.check(child); err != nil {
		t.Fatalf("the child checks at the ledger: %v", err)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	_, err := h.through("maya", "pages", "ledger", sc(ledgerKind, "write"))
	refused(t, err, "a child widens what its owner holds through binding \"ledger\"")
	_, err = h.through("remi", "pages", "ledger")
	refused(t, err, "holds no role on pages")
	_, err = h.root("maya", "ledger")
	refused(t, err, "ledger declares no roles")

	h.revoke("pages", "user", "maya", "")
	_, err = h.through("maya", "pages", "ledger")
	refused(t, err, "holds no role on pages")
}

// On a host that installs modules, a module page declaring roles is the
// host's to install, as any module is: the core installs nothing of it and
// offers nothing. Its roles are granted, held and issued at the host's
// active record, which has no principal, never at a record the core retired
// under its own id.
func TestAModulePageOnAHostThatInstallsModulesIsGrantedAtTheHostsRecord(t *testing.T) {
	t.Parallel()
	h := newHostInstalled(t)
	h.store.PutPerson(domain.Person{ID: "maya", Organization: acme})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	if all := h.installations(); len(all) != 0 {
		t.Fatalf("the core installed %v on a host that installs modules", all)
	}
	alex, maya := authority.Person{ID: "alex", Organization: acme, SessionID: "s"}, authority.Person{ID: "maya", Organization: acme, SessionID: "m"}
	if offered, err := h.svc.Offers(h.ctx, alex, acme); err != nil || len(offered) != 0 {
		t.Fatalf("the module page is offered: %v %v", offered, err)
	}
	coreID := authority.StableInstallationID(acme, "pages")
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		if err := tx.PutInstallation(domain.Installation{ID: coreID, Organization: acme, Target: "pages", Status: domain.Revoked, Revision: 3}); err != nil {
			return err
		}
		return tx.PutInstallation(domain.Installation{ID: "host-pages", Organization: acme, Target: "pages", Status: domain.Active, Revision: 1})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.GrantRole(h.ctx, alex, authority.RoleRequest{Organization: acme, InstallationID: "host-pages", Role: "user", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	held, err := h.svc.HeldInstallations(h.ctx, maya, acme)
	if err != nil || len(held) != 1 || held[0].Installation.ID != "host-pages" || !slices.Equal(held[0].Roles, []string{"user"}) {
		t.Fatalf("maya holds %+v (%v), want user at the host's record", held, err)
	}
	issued, err := h.svc.IssueForPerson(h.ctx, maya, authority.IssueRequest{Audience: "pages"})
	if err != nil {
		t.Fatal(err)
	}
	if got := issued.Context.GetSeal().GetInstallationId(); got != "host-pages" {
		t.Fatalf("issued at installation %q, want the host's active record", got)
	}
	exactly(t, issued, "pages.note", "", []string{"read"})
	_, err = h.svc.IssueForPerson(h.ctx, alex, authority.IssueRequest{Audience: "pages"})
	refused(t, err, "alex holds no role on pages")
}

// Two active installations of one target in one organization is a store that
// broke its invariant. Nothing chooses between them: issuance fails closed
// rather than letting store order decide whose grants apply.
func TestSeveralActiveInstallationsOfOneTargetFailClosed(t *testing.T) {
	t.Parallel()
	h := newHostInstalled(t)
	h.record(acme, "host-1", domain.Active, 1)
	if _, err := h.issue(authority.Workload{Module: "store"}, acme); err != nil {
		t.Fatalf("one active installation issues: %v", err)
	}
	h.record(acme, "host-2", domain.Active, 1)
	_, err := h.issue(authority.Workload{Module: "store"}, acme)
	if err == nil || !strings.Contains(err.Error(), "2 active installations") {
		t.Fatalf("two active installations issued, or failed for another reason: %v", err)
	}
}
