package authority_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// pageReachingStore is the module page at generation with a binding to the
// store carrying read and write, its viewer naming the store's kind with
// viewerAtStore and its installer role reading it.
func pageReachingStore(generation uint64, viewerAtStore ...string) domain.Module {
	m := pageModule(generation, true)
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(kind, "read")}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, viewerAtStore...)}
	return m
}

// No consent holds a module page's installation, so an administrator's grant
// of one of its roles is the only approval its holders have: a delivery, of
// the page or of a module it reaches, that widens what the role reaches
// through the page's bindings ends that role's grants, journaled, instead of
// giving the wider reach to people granted the narrower one. A role whose
// reach did not widen keeps its grants; a narrowing keeps every grant; once
// granted again, the wider reach is issued.
func TestADeliveryWideningAPageRolesReachEndsItsGrants(t *testing.T) {
	h := newHarness(t)
	svc, events := journaled(h)
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(1, "read")); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	h.grant("pages", domain.InstallerRole, "remi")
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, "", []string{"read"})
	revision := h.pagesAt(acme).Revision

	// The page widens its viewer to write at the store.
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(2, "read", "write")); err != nil {
		t.Fatal(err)
	}
	_, err := h.through("maya", "pages", "store")
	refused(t, err, "holds no role on pages")
	grants := h.roleGrants("pages")
	if slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == "viewer" }) ||
		!slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == domain.InstallerRole && g.PersonID == "remi" }) {
		t.Fatalf("after the viewer's reach widened the grants are %+v, want remi's installer grant alone", grants)
	}
	if got := h.pagesAt(acme).Revision; got != revision+1 {
		t.Fatalf("the installation's revision is %d, want %d", got, revision+1)
	}
	e, ok := lastEvent(*events, domain.InstallationRoleReachWidened)
	if !ok || e.Detail["roles"] != "viewer" || !strings.Contains(e.Detail["widened"], "further at pages > store") {
		t.Fatalf("installation.role_reach_widened: %+v %v", e, ok)
	}
	if e, ok := lastEvent(*events, domain.RoleRevoked); !ok || e.Detail["person"] != "maya" || e.Actor != "delivery:pages" {
		t.Fatalf("maya's grant was not journaled as revoked by the delivery: %+v %v", e, ok)
	}
	exactly(t, h.must(h.through("remi", "pages", "store")), kind, "", []string{"read"})

	// Granted again, the wider reach is issued.
	h.grant("pages", "viewer", "maya")
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, "", []string{"read", "write"})

	// A module the page reaches adding an operation the viewer reaches
	// widens it too; the installer's reach there gains the operation as
	// well, so both roles' grants end.
	if _, err := svc.ApplyModule(h.ctx, storeAt(2, "write", false)); err != nil {
		t.Fatal(err)
	}
	if grants := h.roleGrants("pages"); len(grants) != 0 {
		t.Fatalf("a downstream widening kept grants: %+v", grants)
	}

	// A narrowing keeps every grant.
	h.grant("pages", "viewer", "maya")
	if _, err := svc.ApplyModule(h.ctx, pageReachingStore(3, "read")); err != nil {
		t.Fatal(err)
	}
	if grants := h.roleGrants("pages"); !slices.ContainsFunc(grants, func(g domain.RoleGrant) bool { return g.Role == "viewer" && g.PersonID == "maya" }) {
		t.Fatalf("a narrowing ended the viewer's grant: %+v", grants)
	}
	exactly(t, h.must(h.through("maya", "pages", "store")), kind, "", []string{"read"})
}
