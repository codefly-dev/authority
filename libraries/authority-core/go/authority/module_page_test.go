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
// it is the roles granted them on its organization's installation, and it is
// chosen by an administrator's review, as a solution is. It declares no
// standing authority of its own.
func pageModule(generation uint64, roles bool) domain.Module {
	m := domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Generation: generation, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}}
	if roles {
		m.InstallationRole = domain.NoInstallationRole
		m.Roles = map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {sc("pages.note", "read", "write")},
			"viewer":             {sc("pages.note", "read")},
		}
	}
	return m
}

// A module page declaring roles is offered, reviewed and installed like a
// solution: composition does not install it, an administrator's review hands
// Install its consent tuple, and the installation is theirs to grant on and
// to uninstall. Its role holder is entitled to exactly the role; another
// member, one whose organization role covers the kind included, is not; an
// undeclared role is refused; a revoke ends it. Redelivered without roles,
// the module is the organization's again, present at every organization:
// the role's capabilities end and organization roles decide, as for any
// module, until it declares roles again, when it is chosen again.
func TestAModulePageIsOfferedReviewedAndInstalledLikeASolution(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "page-reader", Scopes: []domain.RoleScope{{Kind: "pages.note", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "ines", Organization: acme, Roles: []string{"page-reader"}})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	// Delivered, it is installed nowhere: it is chosen, not composition's.
	for _, org := range []string{acme, globex} {
		if all, err := h.svc.Installations(h.ctx, h.admin(org), org); err != nil || slices.ContainsFunc(all, func(i domain.Installation) bool { return i.Target == "pages" }) {
			t.Fatalf("composition installed the module page at %s: %v %v", org, all, err)
		}
	}
	_, err := h.root("maya", "pages")
	code(t, err, domain.Precondition)

	// The administrator's Setup lists it beside the solutions, never the
	// bare store; a member's read of the list is refused.
	if names := h.offers(acme); !slices.Contains(names, "pages") || !slices.Contains(names, "a") || slices.Contains(names, "store") {
		t.Fatalf("the offers are the solutions and the module page, not the bare store: %v", names)
	}
	_, err = h.svc.Offers(h.ctx, h.person("maya"), acme)
	code(t, err, domain.Denied)
	// Its review is a solution's: the roles its Setup shows, the consent
	// tuple Install takes, and what the target is.
	offer, err := h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "pages")
	if err != nil || len(offer.Module.Roles) != 2 || offer.Installation.ID != "" || offer.Approval.Digest == "" || offer.Approval.Generation != 1 ||
		!offer.RolesDeclared || !offer.Page || len(offer.Closure) != 0 {
		t.Fatalf("the administrator reviews the module page's offer: %+v, %v", offer, err)
	}
	// A made-up tuple is refused for what it says, as a solution's is.
	made := &domain.ConsentApproval{TargetID: "pages", Generation: 1, Digest: "sha256:made-up", OperationID: uuid.NewString()}
	_, err = h.svc.Install(h.ctx, h.admin(acme), acme, "pages", "", "", made, nil)
	refused(t, err, "INSTALLATION_APPROVAL_DIGEST_CHANGED")
	// The install: no step (a module page declares no install endpoint), so
	// active at once, with a principal and no standing authority.
	inst := h.installAs(acme, "pages", "")
	if inst.Status != domain.Active || inst.AgentRole != domain.NoInstallationRole || inst.PrincipalID == "" || inst.ID != h.inst(acme, "pages").ID {
		t.Fatalf("install: %+v", inst)
	}
	if offer, err = h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "pages"); err != nil || offer.Installation.ID != inst.ID {
		t.Fatalf("the review names the installation: %+v, %v", offer, err)
	}
	// Globex has not chosen it: nobody is entitled there.
	_, err = h.root("zoe", "pages")
	code(t, err, domain.Precondition)

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
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "editor", PersonID: "remi"})
	refused(t, err, `pages declares no role "editor"`)

	h.revoke("pages", "viewer", "maya", "")
	_, err = h.root("maya", "pages")
	refused(t, err, "maya holds no role on pages")
	if _, err := h.svc.ListResources(h.ctx, viewer.Token, "pages", "pages.note", "read"); err == nil {
		t.Fatal("a revoked viewer still lists the page's notes")
	}
	h.grant("pages", "viewer", "maya")
	viewer = h.must(h.root("maya", "pages"))

	// Without roles it is composition's: present at globex now, acme's
	// chosen installation kept, nothing to review or offer.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(2, false)); err != nil {
		t.Fatal(err)
	}
	if err := h.check(viewer); err == nil {
		t.Fatal("a role's capability outlived the module withdrawing its roles")
	}
	reader := h.must(h.root("ines", "pages"))
	exactly(t, reader, "pages.note", "", []string{"read"})
	if kept, err := h.svc.Installations(h.ctx, h.admin(acme), acme); err != nil || !slices.ContainsFunc(kept, func(i domain.Installation) bool { return i.ID == inst.ID && i.Status == domain.Active }) {
		t.Fatalf("the chosen installation did not survive the module becoming composition's: %v %v", kept, err)
	}
	if there, err := h.svc.Installations(h.ctx, h.admin(globex), globex); err != nil || !slices.ContainsFunc(there, func(i domain.Installation) bool {
		return i.Target == "pages" && i.Status == domain.Active && i.PrincipalID == ""
	}) {
		t.Fatalf("composition did not install the module at globex: %v %v", there, err)
	}
	_, err = h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "pages")
	refused(t, err, "a module without roles is installed by composition")
	_, err = h.svc.Install(h.ctx, h.admin(globex), globex, "pages", "", "", made, nil)
	code(t, err, domain.NotFound)
	if names := h.offers(acme); slices.Contains(names, "pages") {
		t.Fatalf("a module page withdrawing its roles is still offered: %v", names)
	}
	_, err = h.root("maya", "pages")
	refused(t, err, "holds nothing")
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"})
	refused(t, err, `pages declares no role "viewer"`)

	// Declaring roles again ends what the organization's roles issued, and
	// the module is chosen again: globex's composition installation ends,
	// acme's chosen one stands and is upgraded in place by its administrator.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(3, true)); err != nil {
		t.Fatal(err)
	}
	if err := h.check(reader); err == nil {
		t.Fatal("an organization role's capability outlived the module declaring its own roles")
	}
	if there, err := h.svc.Installations(h.ctx, h.admin(globex), globex); err != nil || slices.ContainsFunc(there, func(i domain.Installation) bool { return i.Target == "pages" && i.Status == domain.Active }) {
		t.Fatalf("globex's composition installation survived the module being chosen: %v %v", there, err)
	}
	if up := h.installAs(acme, "pages", ""); up.ID != inst.ID || up.Status != domain.Active || up.Consent.Generation != 3 {
		t.Fatalf("upgrade: %+v", up)
	}
	h.grant("pages", "viewer", "maya")
	exactly(t, h.must(h.root("maya", "pages")), "pages.note", "", []string{"read"})
	// Chosen, it is uninstalled by its administrator, as a solution is.
	if err := h.svc.Uninstall(h.ctx, h.admin(acme), acme, inst.ID); err != nil {
		t.Fatal(err)
	}
	_, err = h.root("maya", "pages")
	code(t, err, domain.Precondition)
}

// A module declaring no roles is never offered or installed by an
// administrator: composition installs it, and Install refuses it by name.
func TestAModuleWithoutRolesIsNeverOfferedOrInstalled(t *testing.T) {
	h := newHarness(t)
	if names := h.offers(acme); slices.Contains(names, "store") || slices.Contains(names, "legacy-store") {
		t.Fatalf("a module without roles is offered: %v", names)
	}
	_, err := h.svc.Review(h.ctx, h.admin(acme), acme, "store")
	code(t, err, domain.NotFound)
	made := &domain.ConsentApproval{TargetID: "store", Generation: 1, Digest: "sha256:made-up", OperationID: uuid.NewString()}
	_, err = h.svc.Install(h.ctx, h.admin(acme), acme, "store", "", "", made, nil)
	code(t, err, domain.NotFound)
	refused(t, err, "a module without roles is installed by composition")
	_, err = h.svc.InstallAsHost(h.ctx, acme, "store", "", "alex", nil)
	code(t, err, domain.NotFound)
	// It is installed by composition at every organization, holding no
	// principal, and a person cannot uninstall it.
	for _, org := range []string{acme, globex} {
		all, err := h.svc.Installations(h.ctx, h.admin(org), org)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(all, func(i domain.Installation) bool { return i.Target == "store" })
		if i < 0 || all[i].Status != domain.Active || all[i].PrincipalID != "" {
			t.Fatalf("composition did not install the store at %s: %v", org, all)
		}
		err = h.svc.Uninstall(h.ctx, h.admin(org), org, all[i].ID)
		refused(t, err, "installed by composition")
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
