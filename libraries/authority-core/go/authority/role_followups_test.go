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

// A redelivery that drops a role drops its grants with it, on a solution and
// on a module page alike: a later generation declaring the name again, wider,
// finds no holder, and nobody holds a role an administrator never granted
// under that meaning.
func TestARedeliveryDroppingARoleDropsItsGrants(t *testing.T) {
	h := newHarness(t)
	roles := solution("a", true).Roles
	h.grant("a", "viewer", "maya")
	h.grantTeam("a", "viewer", "team")
	h.grant("a", "editor", "remi")
	exactly(t, h.must(h.root("maya", "a")), "a.note", h.principal(acme, "a"), []string{"read"})

	without := map[string][]*basev0.WorkScopeV1{}
	for name, scopes := range roles {
		if name != "viewer" {
			without[name] = scopes
		}
	}
	if _, err := h.svc.ApplyModule(h.ctx, at("a", 2, without)); err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"maya", "tam"} {
		_, err := h.root(person, "a")
		refused(t, err, "holds no role")
	}
	if grants := h.roleGrants("a"); slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == "viewer" }) ||
		!slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == "editor" && g.PersonID == "remi" }) {
		t.Fatalf("the dropped role's grants stay, or another role's went: %v", grants)
	}
	exactly(t, h.must(h.root("remi", "a")), "a.note", h.principal(acme, "a"), []string{"read"})

	// Declared again, and wider: the old holders hold nothing until granted.
	wider := map[string][]*basev0.WorkScopeV1{}
	for name, scopes := range roles {
		wider[name] = scopes
	}
	wider["viewer"] = []*basev0.WorkScopeV1{sc("a.note", "read", "write")}
	if _, err := h.svc.ApplyModule(h.ctx, at("a", 3, wider)); err != nil {
		t.Fatal(err)
	}
	_, err := h.root("maya", "a")
	refused(t, err, "holds no role")
	// The wider declaration asks more: an administrator upgrades to it
	// before its viewer can be granted.
	h.install(acme, "a")
	h.grant("a", "viewer", "maya")
	exactly(t, h.must(h.root("maya", "a")), "a.note", h.principal(acme, "a"), []string{"read", "write"})

	// A module page redelivered without roles drops them all from its
	// composition installation; declaring roles again entitles nobody.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	exactly(t, h.must(h.root("maya", "pages")), "pages.note", "", []string{"read"})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(2, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(3, true)); err != nil {
		t.Fatal(err)
	}
	_, err = h.root("maya", "pages")
	refused(t, err, "holds no role")
	if grants := h.roleGrants("pages"); len(grants) != 0 {
		t.Fatalf("a module page's dropped roles kept their grants: %v", grants)
	}
}

// A module page's role reaches through the page's bindings as a solution's
// does: it may name what a binding consumes, and, declared through that
// binding, what the modules it reaches consume onward (the store's own
// binding carries the kind's write); never what nothing reaches, nor a kind
// reached downstream it does not declare through its binding.
func TestAModulePageRoleNamesWhatItServesOrConsumes(t *testing.T) {
	h := newHarness(t)
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read")}}}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatalf("a page role naming what its binding consumes is accepted: %v", err)
	}
	m.Generation = 2
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read", "write")}
	_, err := h.svc.ApplyModule(h.ctx, m)
	refused(t, err, "grants beyond what pages serves or explicitly consumes")
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"viewer": {"store": {sc(kind, "write")}}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatalf("the store's own binding reaches the kind's write, so a role may name it through the binding: %v", err)
	}
	m.Generation = 3
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read"), sc("unreached.kind", "read")}
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"viewer": {"store": {sc("unreached.kind", "read")}}}
	_, err = h.svc.ApplyModule(h.ctx, m)
	refused(t, err, `names unreached.kind:read through binding "store", which reaches it nowhere`)
}

// A person holding only a module page's role is issued, through the page's
// binding, a child narrowed to the role intersected with the binding, and
// nothing beyond: not an action the binding does not carry, not an action the
// role does not grant, not without the role, and not on their own session at
// the module the page reaches, where their own grants still decide.
func TestAModulePageRoleReachesThroughThePagesBinding(t *testing.T) {
	h := newHarness(t)
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{
		"store":  {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}},
		"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
	}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(kind, "read", "write")}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read"), sc(legacyKind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")

	child := h.must(h.through("maya", "pages", "store"))
	exactly(t, child, kind, "", []string{"read"})
	if err := h.check(child); err != nil {
		t.Fatalf("the child checks at the store: %v", err)
	}
	// A page's role selects no owner, so a module that checks none is reached
	// as well: only a solution's roles confine to its principal's data.
	exactly(t, h.must(h.through("maya", "pages", "legacy")), legacyKind, "", []string{"read"})
	_, err := h.through("maya", "pages", "store", sc(kind, "write"))
	refused(t, err, "a child widens what its owner holds through binding \"store\"")
	_, err = h.through("remi", "pages", "store")
	refused(t, err, "holds no role on pages")
	_, err = h.root("maya", "store")
	refused(t, err, "the owner holds nothing at this audience")

	h.revoke("pages", "viewer", "maya", "")
	_, err = h.through("maya", "pages", "store")
	refused(t, err, "holds no role on pages")
}

// On a host that installs modules, a module page declaring roles is the
// host's to install, as any module is: the core installs nothing of it and
// offers nothing. Its roles are granted, held and issued at the host's
// active record, which has no principal, never at a record the core retired
// under its own id.
func TestAModulePageOnAHostThatInstallsModulesIsGrantedAtTheHostsRecord(t *testing.T) {
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
	if _, err := h.svc.GrantRole(h.ctx, alex, authority.RoleRequest{Organization: acme, InstallationID: "host-pages", Role: "viewer", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	held, err := h.svc.HeldInstallations(h.ctx, maya, acme)
	if err != nil || len(held) != 1 || held[0].Installation.ID != "host-pages" || !slices.Equal(held[0].Roles, []string{"viewer"}) {
		t.Fatalf("maya holds %+v (%v), want viewer at the host's record", held, err)
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
