package authority_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The roles are admin and user, everywhere. These are the only tests that
// name another role: each proves the name is refused, or holds nothing.

// twoRolePage is the module page declaring its two roles, user holding
// actions on the page's own kind.
func twoRolePage(generation uint64, user ...string) domain.Module {
	m := pageModule(generation, false)
	m.Roles = map[string][]*basev0.WorkScopeV1{domain.AdminRole: {sc("pages.note", "read", "write")}, domain.UserRole: {sc("pages.note", user...)}}
	return m
}

func (h *harness) grantAs(caller, role, person string) error {
	_, err := h.svc.GrantRole(h.ctx, h.person(caller), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "pages").ID, Role: role, PersonID: person})
	return err
}

// withRoles is solution name at generation, declaring roles, read from source.
func withRoles(name string, generation uint64, source string, roles map[string][]*basev0.WorkScopeV1) domain.Module {
	m := solution(name, true)
	m.Generation, m.Source, m.Roles = generation, source, roles
	m.InstallationRole = domain.NoInstallationRole
	return m
}

// oldNames is what a host composed before the roles were admin and user
// still holds: solution "old" at generation 1 declaring installer, editor,
// viewer and steward, installed at acme by its administrator, with a grant
// of each. No delivery composes this any more, so it is written to the store
// as that host left it, never through the Service.
func (h *harness) oldNames() domain.Module {
	h.t.Helper()
	own, read := sc("old.note", "read", "write"), sc("old.note", "read")
	m := withRoles("old", 1, "held-1", map[string][]*basev0.WorkScopeV1{
		"installer": {own, sc(kind, "admin", "create", "read", "write")}, "editor": {own, sc(kind, "read", "write")},
		"viewer": {read, sc(kind, "read")}, "steward": {own},
	})
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutModule(m) }); err != nil {
		h.t.Fatal(err)
	}
	inst := h.installAs(acme, "old", "")
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error {
		for _, g := range []domain.RoleGrant{
			{InstallationID: inst.ID, Role: "installer", PersonID: "remi"}, {InstallationID: inst.ID, Role: "editor", PersonID: "ines"},
			{InstallationID: inst.ID, Role: "viewer", PersonID: "maya"}, {InstallationID: inst.ID, Role: "steward", TeamID: "team"},
		} {
			if err := tx.PutRoleGrant(g); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.t.Fatal(err)
	}
	return m
}

// A delivery declaring any role but admin and user is refused by that name,
// admitted or applied, for a solution and for a module page: beside the two,
// or in place of one. "installer" is no admin role: a declaration naming it
// in admin's place declares none.
func TestADeliveryDeclaringARoleThatIsNeitherAdminNorUserIsRefusedByName(t *testing.T) {
	h := newHarness(t)
	own := sc("fresh.note", "read", "write")
	note := sc("pages.note", "read")
	deliveries := map[string]func(roles map[string][]*basev0.WorkScopeV1) domain.Module{
		"a solution": func(roles map[string][]*basev0.WorkScopeV1) domain.Module {
			for name := range roles {
				roles[name] = []*basev0.WorkScopeV1{own}
			}
			return withRoles("fresh", 1, "new-1", roles)
		},
		"a module page": func(roles map[string][]*basev0.WorkScopeV1) domain.Module {
			m := pageModule(1, false)
			for name := range roles {
				roles[name] = []*basev0.WorkScopeV1{note}
			}
			m.Roles = roles
			return m
		},
	}
	for target, delivery := range deliveries {
		for _, name := range []string{"installer", "editor", "viewer", "steward", "author", "reader"} {
			for shape, c := range map[string]struct {
				roles   []string
				refusal string
			}{
				"beside admin and user": {[]string{"admin", "user", name}, `declares role "` + name + `", which is neither "admin" nor "user"`},
				"in place of admin":     {[]string{name, "user"}, `none is "admin"`},
				"in place of user":      {[]string{"admin", name}, `declares role "` + name + `", which is neither "admin" nor "user"`},
			} {
				roles := map[string][]*basev0.WorkScopeV1{}
				for _, r := range c.roles {
					roles[r] = nil
				}
				m := delivery(roles)
				if err := h.svc.Admit(h.ctx, m); err == nil || !strings.Contains(err.Error(), c.refusal) {
					t.Errorf("%s declaring %s %s: Admit answered %v, want a refusal naming %q", target, name, shape, err, c.refusal)
				}
				if _, err := h.svc.ApplyModule(h.ctx, m); err == nil || !strings.Contains(err.Error(), c.refusal) {
					t.Errorf("%s declaring %s %s: ApplyModule answered %v, want a refusal naming %q", target, name, shape, err, c.refusal)
				}
			}
		}
		m := delivery(map[string][]*basev0.WorkScopeV1{"admin": nil, "user": nil})
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Errorf("%s declaring admin and user: %v", target, err)
		}
	}
}

// A role named anything but admin and user holds nothing and administers
// nothing, even where a declaration the core still holds from before names
// it and a grant of it is still in the store: its holder is issued nothing,
// grants nothing, may act as no team, and nobody is granted it.
func TestAStoredGrantOfAnOldRoleNameHoldsAndAdministersNothing(t *testing.T) {
	h := newHarness(t)
	h.oldNames()
	inst := h.inst(acme, "old").ID

	for _, person := range []string{"remi", "ines", "maya", "tam"} {
		_, err := h.root(person, "old")
		refused(t, err, "holds no role")
	}
	// remi holds "installer", once the admin role's name: it administers nothing.
	if _, err := h.svc.GrantRole(h.ctx, h.person("remi"), authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "dev"}); err == nil {
		t.Fatal("a holder of a role named installer granted a role")
	}
	if _, err := h.svc.ListRoleGrants(h.ctx, h.person("remi"), acme, inst); err == nil {
		t.Fatal("a holder of a role named installer listed the installation's grants")
	}
	if _, err := h.svc.RevokeRole(h.ctx, h.person("remi"), authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "maya"}); err == nil {
		t.Fatal("a holder of a role named installer revoked a role")
	}
	if _, err := h.casting("remi", "team"); err == nil {
		t.Fatal("a holder of a role named installer acts as a team")
	}
	// Nor does the organization's administrator grant a role of such a name.
	for _, name := range []string{"installer", "editor", "viewer", "steward"} {
		_, err := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst, Role: name, PersonID: "dev"})
		refused(t, err, `role "`+name+`" is neither "admin" nor "user"`)
	}
	// What is left in the store is still revocable.
	h.revoke("old", "viewer", "maya", "")
	if slices.ContainsFunc(h.roleGrants("old"), func(g domain.RoleGrant) bool { return g.Role == "viewer" }) {
		t.Fatal("a stored grant of an old role name was not revoked")
	}
}

// Nothing converts: when admin and user are delivered over a declaration of
// old names, the installation is held at what it approved and its grants
// stand, holding nothing; when the administrator approves the upgrade, the
// grants of the names it no longer declares end, journaled as revocations by
// the upgrader, and nobody is granted admin or user for having held one. An
// administrator grants the two roles afresh.
func TestGrantsOfOldRoleNamesEndAndNobodyIsMovedToAdminOrUser(t *testing.T) {
	h := newHarness(t)
	h.oldNames()
	svc, events := journaled(h)
	own := sc("old.note", "read", "write")
	next := withRoles("old", 2, "new-2", map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own}, domain.UserRole: {sc("old.note", "read")}})
	if _, err := svc.ApplyModule(h.ctx, next); err != nil {
		t.Fatalf("the delivery of admin and user: %v", err)
	}
	if got := h.roleGrants("old"); len(got) != 4 {
		t.Fatalf("the delivery touched the grants of an installation held at its consent: %v", got)
	}
	alex := h.person("alex")
	if _, err := svc.Install(h.ctx, alex, acme, "old", "", alex.ID, h.approval(acme, "old"), nil); err != nil {
		t.Fatalf("the administrator approves the delivery of admin and user: %v", err)
	}
	if got := h.roleGrants("old"); len(got) != 0 {
		t.Fatalf("the approval left grants %v, want none: an old name's grant ends and none is made", got)
	}
	revoked := 0
	for _, e := range *events {
		switch e.Kind {
		case domain.RoleGranted:
			t.Fatalf("a role was granted by the delivery or its approval: %+v", e)
		case domain.RoleRevoked:
			if e.Actor != "alex" {
				t.Fatalf("an old grant was not journaled as revoked by the upgrader: %+v", e)
			}
			revoked++
		}
	}
	if revoked != 4 {
		t.Fatalf("%d revocations journaled, want one for each of the four old grants", revoked)
	}
	for _, person := range []string{"remi", "ines", "maya", "tam"} {
		_, err := h.root(person, "old")
		refused(t, err, "holds no role")
	}
	h.grant("old", domain.AdminRole, "remi")
	if _, err := h.svc.GrantRole(h.ctx, h.person("remi"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "old").ID, Role: domain.UserRole, PersonID: "maya"}); err != nil {
		t.Fatalf("remi, granted admin by the administrator, grants user: %v", err)
	}
}

// No path composes another name: a generation the core holds from before,
// read again at its host's start (RereadModule), delivered again (a replay)
// or admitted again, is refused by the name it declares, as a new generation
// is; the host is delivered admin and user, which composes.
func TestAGenerationHeldUnderOldRoleNamesIsRefusedByNameWhenReadAgain(t *testing.T) {
	h := newHarness(t)
	h.oldNames()
	own := sc("old.note", "read", "write")
	// Another one held: admin and user, and a third name beside them.
	third := withRoles("third", 1, "held-1", map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own}, domain.UserRole: {own}, "viewer": {own}})
	third.ResourceKinds = []*basev0.WorkScopeV1{own}
	old := withRoles("old", 1, "held-1", nil)
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) { old, err = tx.ModuleNamed("old"); return err }); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutModule(third) }); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		held    domain.Module
		refusal string
	}{
		"old names in place of the two": {old, `none is "admin"`},
		"a third name beside the two":   {third, `declares role "viewer", which is neither "admin" nor "user"`},
	} {
		if _, err := h.svc.RereadModule(h.ctx, c.held); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Errorf("%s, read again: %v, want a refusal naming %q", name, err, c.refusal)
		}
		if _, err := h.svc.ApplyModule(h.ctx, c.held); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Errorf("%s, delivered again: %v, want a refusal naming %q", name, err, c.refusal)
		}
		if err := h.svc.Admit(h.ctx, c.held); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Errorf("%s, admitted again: %v, want a refusal naming %q", name, err, c.refusal)
		}
		next := c.held
		next.Generation, next.Source = 2, "new-2"
		next.Roles = map[string][]*basev0.WorkScopeV1{domain.AdminRole: {own}, domain.UserRole: {own}}
		if name == "a third name beside the two" {
			next.ResourceKinds = []*basev0.WorkScopeV1{own}
		}
		if _, err := h.svc.ApplyModule(h.ctx, next); err != nil {
			t.Errorf("%s: the next delivery declaring admin and user: %v", name, err)
		}
	}
}

// A user approves no page update and administers no grant; the admin does.
func TestAUserNeitherApprovesNorAdministersAPage(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, twoRolePage(1, "read")); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", domain.AdminRole, "remi")
	h.grant("pages", domain.UserRole, "maya")
	if _, err := h.svc.ApplyModule(h.ctx, twoRolePage(2, "read", "write")); err != nil {
		t.Fatal(err)
	}
	_, err := h.approvePage(h.svc, "maya")
	refused(t, err, "requires an administrator or owner")
	code(t, h.grantAs("maya", domain.UserRole, "dev"), domain.Denied)
	if up, err := h.approvePage(h.svc, "remi"); err != nil || up.Consent.Generation != 2 {
		t.Fatalf("the admin's approval: %+v %v", up.Consent, err)
	}
}
