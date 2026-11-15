package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// STOPGAP, one release: a module page delivered before the rename still
// declares "installer" for its admin role. It is installed, and the holder
// of "installer" administers its grants and approves its pending update as
// an admin holder does. Delete with domain.LegacyInstallerRole.
func TestALegacyInstallerHolderAdministersAndApprovesAPage(t *testing.T) {
	h := newHarness(t)
	legacy := func(generation uint64) domain.Module {
		m := pageModule(generation, true)
		m.Roles[domain.LegacyInstallerRole] = m.Roles[domain.AdminRole]
		delete(m.Roles, domain.AdminRole)
		return m
	}
	if _, err := h.svc.ApplyModule(h.ctx, legacy(1)); err != nil {
		t.Fatalf("a page declaring installer is refused: %v", err)
	}
	h.grant("pages", domain.LegacyInstallerRole, "remi")
	h.grant("pages", "reader", "maya")

	// A reader approves and grants nothing; the installer holder does both.
	widened := legacy(2)
	widened.Roles[domain.UserRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	if _, err := h.svc.ApplyModule(h.ctx, widened); err != nil {
		t.Fatal(err)
	}
	if _, err := h.approvePage(h.svc, "maya"); err == nil {
		t.Fatal("a reader approved the page's update")
	}
	if up, err := h.approvePage(h.svc, "remi"); err != nil || up.Consent.Generation != 2 {
		t.Fatalf("the installer holder's approval: %+v %v", up.Consent, err)
	}
	if _, err := h.svc.GrantRole(h.ctx, h.person("remi"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "pages").ID, Role: domain.UserRole, PersonID: "dev"}); err != nil {
		t.Fatalf("the installer holder grants: %v", err)
	}
	if _, err := h.svc.GrantRole(h.ctx, h.person("maya"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "pages").ID, Role: domain.UserRole, PersonID: "dev"}); err == nil {
		t.Fatal("a reader granted a role")
	}
}
