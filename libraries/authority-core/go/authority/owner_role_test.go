package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// The organisation role that administers is "admin" and no other name. A
// person whose only organisation role is called "owner" administers nothing:
// no inventory, no review, no install, no uninstall, no grant.
func TestARoleNamedOwnerAdministersNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.store.PutPerson(domain.Person{ID: "olga", Organization: acme, Roles: []string{"owner"}})
	olga, inst := h.person("olga"), h.inst(acme, "a").ID
	_, err := h.svc.Installations(h.ctx, olga, acme)
	refused(t, err, `installation administration requires an administrator of organization "acme"`)
	code(t, err, domain.Denied)
	_, err = h.svc.Review(h.ctx, olga, acme, "c")
	refused(t, err, `requires an administrator of organization "acme"`)
	_, err = h.svc.Install(h.ctx, olga, acme, "c", "admin", olga.ID, h.approval(acme, "c"), nil)
	refused(t, err, `installation administration requires an administrator of organization "acme"`)
	refused(t, h.svc.Uninstall(h.ctx, olga, acme, inst), "olga is not an administrator of acme")
	_, err = h.svc.GrantRole(h.ctx, olga, authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "admin", PersonID: "olga"})
	refused(t, err, "olga is neither an administrator of acme nor a holder of the admin role")
	if installed, err := h.svc.Installations(h.ctx, h.admin(acme), acme); err != nil || !activeIn(installed, inst) {
		t.Fatalf("a refused owner changed the installation: %v", err)
	}
}
