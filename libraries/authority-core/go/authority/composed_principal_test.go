package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// hostComposedPage is the RBAC-1 module page under a host that installs its
// modules itself (Config.HostInstallsModules): delivery installs nothing, and
// the host writes the page's composition record at acme, without a principal,
// as it did before it asked the core for one. Maya is a viewer there.
func hostComposedPage(t *testing.T) (*harness, domain.Installation) {
	t.Helper()
	h := newHarness(t)
	cfg := h.cfg
	cfg.HostInstallsModules = true
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.svc, h.cfg = svc, cfg
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{
		"store":  {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}},
		"legacy": {ID: "legacy", Audience: "legacy-store", InvokeScopes: []*basev0.WorkScopeV1{sc(legacyKind, "read")}},
	}
	m.Roles[domain.InstallerRole] = append(m.Roles[domain.InstallerRole], sc(kind, "read", "write"), sc(legacyKind, "read"))
	m.Roles["viewer"] = append(m.Roles["viewer"], sc(kind, "read"), sc(legacyKind, "read"))
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	inst := domain.Installation{ID: authority.StableInstallationID(acme, "pages"), Organization: acme, Target: "pages", Status: domain.Active, Revision: 1}
	hostWrites(t, h, inst)
	h.grant("pages", "viewer", "maya")
	return h, inst
}

func hostWrites(t *testing.T, h *harness, inst domain.Installation) {
	t.Helper()
	if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
		t.Fatal(err)
	}
}

// RBAC-1 for a host that installs its modules: the core makes no composition
// installation there, so it never gives one a principal, and a module page's
// role then reaches nothing of a module that checks owners. The host asks
// ComposedPrincipal and persists the answer on its record at a raised
// revision: the page's role reaches the owner-aware store as that
// installation's data, exactly as on a core that composes, and what was issued
// before the record held its principal ends.
func TestAHostThatInstallsModulesGivesAModulePageItsComposedPrincipal(t *testing.T) {
	h, inst := hostComposedPage(t)
	if all, err := h.svc.Installations(h.ctx, h.admin(acme), acme); err != nil {
		t.Fatal(err)
	} else {
		for _, i := range all {
			if i.Target == "pages" && i.PrincipalID != "" {
				t.Fatalf("the core gave the host's record a principal itself: %+v", i)
			}
		}
	}
	_, err := h.page("maya", "pages", "store")
	refused(t, err, `holds nothing at store through binding "store"`)
	before := h.must(h.page("maya", "pages", "legacy-store"))

	principal, err := h.svc.ComposedPrincipal(h.ctx, acme, "pages", inst.ID)
	if err != nil {
		t.Fatal(err)
	}
	if principal != authority.StablePrincipalID(acme, "pages") {
		t.Fatalf("ComposedPrincipal = %q, want the principal a composing core gives (%q)", principal, authority.StablePrincipalID(acme, "pages"))
	}
	inst.PrincipalID, inst.Revision = principal, inst.Revision+1
	hostWrites(t, h, inst)

	got := h.must(h.page("maya", "pages", "store"))
	exactly(t, got, kind, principal, []string{"read"})
	if err := h.check(got); err != nil {
		t.Fatal(err)
	}
	_, err = h.page("maya", "pages", "store", owned(kind, authority.StablePrincipalID(acme, "a"), []string{"read"}))
	refused(t, err, `a child widens what its owner holds through binding "store"`)
	if err := h.check(before); err == nil {
		t.Fatal("a capability sealed before the record held its principal outlived the raise")
	}
}

// A principal another identity holds is never given: ComposedPrincipal
// answers "" and the record keeps none, owning nothing (fails closed), as
// the core's own composition decides. The installation itself is not
// another identity.
func TestComposedPrincipalAnswersNothingForATakenPrincipal(t *testing.T) {
	h, inst := hostComposedPage(t)
	principal := authority.StablePrincipalID(acme, "pages")

	inst.PrincipalID = principal
	hostWrites(t, h, inst)
	if got, err := h.svc.ComposedPrincipal(h.ctx, acme, "pages", inst.ID); err != nil || got != principal {
		t.Fatalf("the installation holding its own principal: %q (%v)", got, err)
	}
	if got, err := h.svc.ComposedPrincipal(h.ctx, acme, "pages", "another-installation"); err != nil || got != "" {
		t.Fatalf("another installation's principal was given: %q (%v)", got, err)
	}

	inst.PrincipalID = ""
	hostWrites(t, h, inst)
	h.store.PutPerson(domain.Person{ID: principal, Organization: acme})
	if got, err := h.svc.ComposedPrincipal(h.ctx, acme, "pages", inst.ID); err != nil || got != "" {
		t.Fatalf("a person's id was given as the principal: %q (%v)", got, err)
	}
}
