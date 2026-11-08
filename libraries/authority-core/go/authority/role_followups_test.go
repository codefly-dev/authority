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

// A module page's role names what the page serves. A role over a kind the
// page only consumes through a binding would be accepted and decide nothing
// (at the module it reaches, a person holds their own grants, cut to the
// binding), so it is refused by name. A solution's roles reach through its
// bindings and may name what they consume, as the harness's do.
func TestAModulePageRoleNamesOnlyWhatItServes(t *testing.T) {
	h := newHarness(t)
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read")}}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatalf("a page consuming a kind through a binding is accepted: %v", err)
	}
	m.Generation = 2
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read")}
	_, err := h.svc.ApplyModule(h.ctx, m)
	refused(t, err, "never reach what it consumes")
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
