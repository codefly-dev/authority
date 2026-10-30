package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// pageModule is a module declaring a page; with roles, what a person holds at
// it is the roles granted them on its organization's installation.
func pageModule(generation uint64, roles bool) domain.Module {
	m := domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Generation: generation, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}}
	if roles {
		m.Roles = map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {sc("pages.note", "read", "write")},
			"viewer":             {sc("pages.note", "read")},
		}
	}
	return m
}

// A module page's role holder is entitled to exactly the role; another member,
// one whose organization role covers the kind included, is not; an undeclared
// role is refused; a revoke ends it. Redelivered without roles, the module is
// the organization's again: the role's capabilities end and organization
// roles decide, as for any module, until it declares roles again.
func TestAModulePageRoleEntitlesItsHolderAlone(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "page-reader", Scopes: []domain.RoleScope{{Kind: "pages.note", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "ines", Organization: acme, Roles: []string{"page-reader"}})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}

	h.grant("pages", "viewer", "maya")
	viewer := h.must(h.root("maya", "pages"))
	exactly(t, viewer, "pages.note", "", []string{"read"})
	if err := h.check(viewer); err != nil {
		t.Fatal(err)
	}
	_, err := h.root("maya", "pages", sc("pages.note", "write"))
	refused(t, err, "beyond")
	heldIs(t, "maya", h.heldBy(h.person("maya"), acme), "pages:[viewer]")
	for _, other := range []string{"remi", "ines", "alex"} {
		_, err := h.root(other, "pages")
		code(t, err, domain.Denied)
		refused(t, err, other+" holds no role on pages")
	}
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "pages").ID, Role: "editor", PersonID: "remi"})
	refused(t, err, `pages declares no role "editor"`)

	h.revoke("pages", "viewer", "maya", "")
	_, err = h.root("maya", "pages")
	refused(t, err, "maya holds no role on pages")
	h.grant("pages", "viewer", "maya")
	viewer = h.must(h.root("maya", "pages"))

	if _, err := h.svc.ApplyModule(h.ctx, pageModule(2, false)); err != nil {
		t.Fatal(err)
	}
	if err := h.check(viewer); err == nil {
		t.Fatal("a role's capability outlived the module withdrawing its roles")
	}
	reader := h.must(h.root("ines", "pages"))
	exactly(t, reader, "pages.note", "", []string{"read"})
	_, err = h.root("maya", "pages")
	refused(t, err, "holds nothing")
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "pages").ID, Role: "viewer", PersonID: "maya"})
	refused(t, err, `pages declares no role "viewer"`)

	// Declaring roles again ends what the organization's roles issued.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(3, true)); err != nil {
		t.Fatal(err)
	}
	if err := h.check(reader); err == nil {
		t.Fatal("an organization role's capability outlived the module declaring its own roles")
	}
}

// A module declaring roles and no page is refused, and nothing of it composes.
func TestAModuleWithoutAPageDeclaresNoRoles(t *testing.T) {
	h := newHarness(t)
	headless := pageModule(1, true)
	headless.Page = false
	_, err := h.svc.ApplyModule(h.ctx, headless)
	refused(t, err, "declares roles and no page")
	_, err = h.root("maya", "pages")
	code(t, err, domain.NotFound)
}
