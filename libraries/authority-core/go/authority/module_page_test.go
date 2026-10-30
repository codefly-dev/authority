package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/google/uuid"
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

	// Its offer is reviewed as a solution's: the roles its Setup shows. Its
	// installation stays composition's, so the review carries no consent
	// tuple, and Install refuses it whatever it is handed.
	offer, err := h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "pages")
	if err != nil || len(offer.Module.Roles) != 2 || offer.Installation.ID != h.inst(acme, "pages").ID || offer.Approval != (domain.ConsentApproval{}) {
		t.Fatalf("the administrator reviews the module page's offer: %+v, %v", offer, err)
	}
	if approval, err := h.svc.Review(h.ctx, h.admin(acme), acme, "pages"); err != nil || approval != (domain.ConsentApproval{}) {
		t.Fatalf("a module page's review answers a consent tuple: %+v, %v", approval, err)
	}
	// Its review answers no tuple to hand Install, and a well-formed tuple
	// made up for it is refused for what the target is.
	_, err = h.svc.Install(h.ctx, h.admin(acme), acme, "pages", "", "", h.approval(acme, "pages"), nil)
	refused(t, err, "INSTALLATION_APPROVAL_REQUIRED")
	made := &domain.ConsentApproval{TargetID: "pages", Generation: 1, Digest: "sha256:made-up", OperationID: uuid.NewString()}
	_, err = h.svc.Install(h.ctx, h.admin(acme), acme, "pages", "", "", made, nil)
	refused(t, err, "a module is installed by composition")
	// The administrator's Setup lists it beside the solutions; a member's
	// read of the list is refused.
	if names := h.offers(acme); !slices.Contains(names, "pages") || !slices.Contains(names, "a") || slices.Contains(names, "store") {
		t.Fatalf("the offers are the solutions and the module page, not the bare store: %v", names)
	}
	_, err = h.svc.Offers(h.ctx, h.person("maya"), acme)
	code(t, err, domain.Denied)

	h.grant("pages", "viewer", "maya")
	viewer := h.must(h.root("maya", "pages"))
	exactly(t, viewer, "pages.note", "", []string{"read"})
	if err := h.check(viewer); err != nil {
		t.Fatal(err)
	}
	// What she may list is her role's, not her organization roles': an
	// organization role naming one note does not narrow it, and no
	// organization role is needed for it.
	listed, err := h.svc.ListResources(h.ctx, viewer.Token, "pages", "pages.note", "read")
	if err != nil || len(listed) != 1 || !listed[0].All || listed[0].Owner != "" {
		t.Fatalf("the viewer lists %v, %v", listed, err)
	}
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "one-note", Scopes: []domain.RoleScope{{Kind: "pages.note", Actions: []string{"read"}, Resources: []resources.Grant{{ID: "x"}}}}})
	h.store.PutPerson(domain.Person{ID: "maya", Organization: acme, Roles: []string{"one-note"}})
	if listed, err = h.svc.ListResources(h.ctx, viewer.Token, "pages", "pages.note", "read"); err != nil || len(listed) != 1 || !listed[0].All {
		t.Fatalf("an organization role narrowed the viewer's listing: %v, %v", listed, err)
	}
	h.store.PutPerson(domain.Person{ID: "maya", Organization: acme})
	_, err = h.root("maya", "pages", sc("pages.note", "write"))
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
	if _, err := h.svc.ListResources(h.ctx, viewer.Token, "pages", "pages.note", "read"); err == nil {
		t.Fatal("a revoked viewer still lists the page's notes")
	}
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
	_, err = h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "pages")
	refused(t, err, "a module is installed by composition")
	if names := h.offers(acme); slices.Contains(names, "pages") {
		t.Fatalf("a module page withdrawing its roles is still offered: %v", names)
	}
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

// offers are the names an administrator of org is offered to set up.
func (h *harness) offers(org string) []string {
	h.t.Helper()
	offered, err := h.svc.Offers(h.ctx, h.admin(org), org)
	if err != nil {
		h.t.Fatal(err)
	}
	var names []string
	for _, m := range offered {
		names = append(names, m.Name)
	}
	return names
}
