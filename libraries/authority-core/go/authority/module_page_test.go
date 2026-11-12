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
// it is the roles granted them on its organization's composition
// installation. It is installed by composition like any module, roles or not.
func pageModule(generation uint64, roles bool) domain.Module {
	m := domain.Module{Name: "pages", Principal: "pages", Kind: domain.KindModule, Generation: generation, Page: true,
		InstallationRole: domain.NoInstallationRole, ResourceKinds: []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}}
	if roles {
		m.Roles = map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {sc("pages.note", "read", "write")},
			"viewer":             {sc("pages.note", "read")},
		}
	}
	return m
}

// pagesAt is the module page's installation at org, as its administrator
// lists it.
func (h *harness) pagesAt(org string) domain.Installation {
	h.t.Helper()
	all, err := h.svc.Installations(h.ctx, h.admin(org), org)
	if err != nil {
		h.t.Fatal(err)
	}
	i := slices.IndexFunc(all, func(i domain.Installation) bool { return i.Target == "pages" })
	if i < 0 {
		h.t.Fatalf("pages is not installed at %s: %v", org, all)
	}
	return all[i]
}

// A module is installed by composition in every organisation: delivered,
// with roles or without, it is installed at each organization, and at one
// added or reconciled later, holding no agent role and no consent: none of
// them through a review. Its principal owns what its page creates in a module
// that checks owners, as a solution installation's does (RBAC-1).
func TestAModuleIsInstalledByCompositionInEveryOrganisation(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{"joined", "missed"} {
		h.store.PutOrganization(domain.Organization{ID: org, Name: org})
	}
	if _, err := h.svc.OrganizationAdded(h.ctx, "joined"); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.ReconcileOrganizations(h.ctx); err != nil {
		t.Fatal(err)
	}
	var all []domain.Installation
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) {
		all, err = tx.Installations("")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{acme, globex, "joined", "missed"} {
		for _, target := range []string{"pages", "store"} {
			i := slices.IndexFunc(all, func(i domain.Installation) bool { return i.Organization == org && i.Target == target })
			if i < 0 {
				t.Fatalf("composition did not install %s at %s: %v", target, org, all)
			}
			// A page's installation holds composition's receipt once the host
			// reconciled (AdoptLegacyReach); a module declaring no role holds none.
			consent := target == "pages"
			if inst := all[i]; inst.ID != h.inst(org, target).ID || inst.Status != domain.Active || inst.PrincipalID != h.principal(org, target) || inst.AgentRole != "" ||
				inst.InstalledBy != "" || (inst.Consent.OperationID == domain.ComposedConsent) != consent || (!consent && inst.Consent != (domain.ConsentReceipt{})) {
				t.Fatalf("%s at %s is not a composition installation: %+v", target, org, inst)
			}
		}
		if slices.ContainsFunc(all, func(i domain.Installation) bool {
			return i.Organization == org && i.Target == "a" && org != acme && org != globex
		}) {
			t.Fatalf("composition installed a solution at %s: %v", org, all)
		}
	}
}

// A module is never offered or installed by an administrator, roles or not:
// ListOffers lists the solutions alone; Install of a module declaring no
// role, or of a page with no approval of its offer, and InstallAsHost of
// either answer NotFound naming composition; a person cannot uninstall its
// installation. A module declaring no role is never reviewed either. A
// page's active installation is reviewed, for the upgrade it offers: the
// tuple an administrator or its installer approves through Install, which
// is a replay of what stands when nothing widened.
func TestAModuleIsNeverOfferedOrInstalledByAnAdministrator(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	if names := h.offers(acme); !slices.Equal(names, []string{"a", "b", "c"}) {
		t.Fatalf("the offers are not the solutions alone: %v", names)
	}
	for _, target := range []string{"pages", "store"} {
		_, err := h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, target)
		if target == "store" {
			code(t, err, domain.NotFound)
			refused(t, err, "a module is installed by composition")
			_, err = h.svc.Review(h.ctx, h.admin(acme), acme, target)
			code(t, err, domain.NotFound)
		} else if err != nil {
			t.Fatalf("a page's active installation is not reviewed: %v", err)
		}
		made := &domain.ConsentApproval{TargetID: target, Generation: 1, Digest: "sha256:made-up", OperationID: uuid.NewString()}
		_, err = h.svc.Install(h.ctx, h.admin(acme), acme, target, "", "", made, nil)
		if target == "store" {
			code(t, err, domain.NotFound)
			refused(t, err, "a module is installed by composition")
		} else {
			refused(t, err, "INSTALLATION_APPROVAL_DIGEST_CHANGED")
		}
		_, err = h.svc.InstallAsHost(h.ctx, acme, target, "", "alex", nil)
		code(t, err, domain.NotFound)
		refused(t, h.svc.Uninstall(h.ctx, h.admin(acme), acme, h.inst(acme, target).ID), "installed by composition")
	}
	// Nothing widened: the page's offer approved again installs nothing new.
	_, err := h.svc.Install(h.ctx, h.admin(acme), acme, "pages", "", "", h.approval(acme, "pages"), nil)
	refused(t, err, "pages is already installed at acme")
}

// A module that gains or loses roles keeps its installation: its id and
// status never move. The grants of a role still declared survive, and what
// they issued stays valid; a role added waits for the upgrade's approval
// before it is granted, as a solution's does; the grants of a role the
// delivered generation drops end with it. Without roles, organization roles
// decide; with roles again, nobody holds one until the upgrade is approved
// and the role granted.
func TestAModuleThatGainsOrLosesRolesKeepsItsInstallation(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "page-reader", Scopes: []domain.RoleScope{{Kind: "pages.note", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "ines", Organization: acme, Roles: []string{"page-reader"}})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, false)); err != nil {
		t.Fatal(err)
	}
	inst := h.pagesAt(acme)
	kept := func(when string) {
		t.Helper()
		if now := h.pagesAt(acme); now.ID != inst.ID || now.Status != domain.Active || now.PrincipalID != h.principal(acme, "pages") {
			t.Fatalf("%s moved the installation: %+v, was %+v", when, now, inst)
		}
	}
	reader := h.must(h.root("ines", "pages"))

	// Gaining roles: the installation stays; organization roles stop deciding.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(2, true)); err != nil {
		t.Fatal(err)
	}
	kept("gaining roles")
	if err := h.check(reader); err == nil {
		t.Fatal("an organization role's capability outlived the module declaring its own roles")
	}
	h.grant("pages", "viewer", "maya")
	viewer := h.must(h.root("maya", "pages"))

	// A role added: the grants and what they issued survive.
	added := pageModule(3, true)
	added.Roles["editor"] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write")}
	if _, err := h.svc.ApplyModule(h.ctx, added); err != nil {
		t.Fatal(err)
	}
	kept("a role added")
	if err := h.check(viewer); err != nil {
		t.Fatalf("a role added ended the viewer's capability: %v", err)
	}
	_, err := h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "editor", PersonID: "remi"})
	refused(t, err, `pages declares no role "editor"`)
	if _, err := h.approvePage(h.svc, "alex"); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "editor", "remi")
	exactly(t, h.must(h.root("remi", "pages")), "pages.note", "", []string{"read", "write"})

	// A role dropped: its grants end; a role still declared keeps its own.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(4, true)); err != nil {
		t.Fatal(err)
	}
	kept("a role dropped")
	if grants := h.roleGrants("pages"); len(grants) != 1 || grants[0].Role != "viewer" || grants[0].PersonID != "maya" {
		t.Fatalf("after editor was dropped the grants are %v, want maya's viewer alone", grants)
	}
	_, err = h.root("remi", "pages")
	refused(t, err, "remi holds no role on pages")
	exactly(t, h.must(h.root("maya", "pages")), "pages.note", "", []string{"read"})

	// Losing every role: the installation stays, the grants and what they
	// issued end, and organization roles decide, as at any module.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(5, false)); err != nil {
		t.Fatal(err)
	}
	kept("losing its roles")
	if err := h.check(viewer); err == nil {
		t.Fatal("a role's capability outlived the module withdrawing its roles")
	}
	if grants := h.roleGrants("pages"); len(grants) != 0 {
		t.Fatalf("the dropped roles kept their grants: %v", grants)
	}
	exactly(t, h.must(h.root("ines", "pages")), "pages.note", "", []string{"read"})
	_, err = h.root("maya", "pages")
	refused(t, err, "holds nothing")
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"})
	refused(t, err, `pages declares no role "viewer"`)

	// Gaining roles again: nobody holds one until the upgrade is approved
	// and the role granted.
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(6, true)); err != nil {
		t.Fatal(err)
	}
	kept("gaining roles again")
	_, err = h.root("maya", "pages")
	refused(t, err, "maya holds no role on pages")
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "viewer", PersonID: "maya"})
	refused(t, err, `pages declares no role "viewer"`)
	if _, err := h.approvePage(h.svc, "alex"); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")
	exactly(t, h.must(h.root("maya", "pages")), "pages.note", "", []string{"read"})
}

// A module page's roles decide who is listed for it and who may use it,
// through grants on its composition installation: a role granted to a team
// lists the page for each member and entitles them to exactly the role; a
// person granted the role holds exactly it, and lists by it whatever their
// organization roles say; another member, one whose organization role
// covers the kind included, holds nothing; another organization's
// installation is its own; an undeclared role is refused; a revoke ends it.
func TestAModulePagesRolesDecideWhoIsListedAndWhoMayUseIt(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "page-reader", Scopes: []domain.RoleScope{{Kind: "pages.note", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "ines", Organization: acme, Roles: []string{"page-reader"}})
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	inst := h.pagesAt(acme)
	for _, p := range []string{"maya", "tam", "ines"} {
		_, err := h.root(p, "pages")
		code(t, err, domain.Denied)
		refused(t, err, p+" holds no role on pages")
	}
	heldIs(t, "tam", h.heldBy(h.person("tam"), acme))

	h.grantTeam("pages", "viewer", "team")
	heldIs(t, "tam", h.heldBy(h.person("tam"), acme), "pages:[viewer]")
	exactly(t, h.must(h.root("tam", "pages")), "pages.note", "", []string{"read"})
	h.revoke("pages", "viewer", "", "team")
	heldIs(t, "tam", h.heldBy(h.person("tam"), acme))

	h.grant("pages", "viewer", "maya")
	viewer := h.must(h.root("maya", "pages"))
	exactly(t, viewer, "pages.note", "", []string{"read"})
	if err := h.check(viewer); err != nil {
		t.Fatal(err)
	}
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
	for _, other := range []string{"remi", "ines"} {
		_, err := h.root(other, "pages")
		refused(t, err, other+" holds no role on pages")
	}
	_, err = h.root("omar", "pages")
	refused(t, err, "omar holds no role on pages")
	_, err = h.svc.GrantRole(h.ctx, h.admin(acme), authority.RoleRequest{Organization: acme, InstallationID: inst.ID, Role: "editor", PersonID: "remi"})
	refused(t, err, `pages declares no role "editor"`)

	h.revoke("pages", "viewer", "maya", "")
	_, err = h.root("maya", "pages")
	refused(t, err, "maya holds no role on pages")
	if _, err := h.svc.ListResources(h.ctx, viewer.Token, "pages", "pages.note", "read"); err == nil {
		t.Fatal("a revoked viewer still lists the page's notes")
	}
}

// Nobody holds a role without a grant: an administrator is refused at a
// solution and at a module page exactly as any member is, and holds what a
// grant gives them once granted. An administrator's power is to grant.
func TestNobodyHoldsARoleWithoutAGrant(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"a", "pages"} {
		for _, p := range []string{"alex", "maya"} {
			_, err := h.root(p, target)
			code(t, err, domain.Denied)
			refused(t, err, p+" holds no role on "+target)
		}
	}
	_, err := h.root("zoe", "a")
	refused(t, err, "zoe holds no role on a")
	heldIs(t, "alex", h.heldBy(h.admin(acme), acme))
	h.grant("pages", "viewer", "alex")
	exactly(t, h.must(h.root("alex", "pages")), "pages.note", "", []string{"read"})
	heldIs(t, "alex", h.heldBy(h.admin(acme), acme), "pages:[viewer]")
}

// A module page holds no standing machine authority, whatever its delivery
// selects: its composition installation has no agent role (its principal owns
// its page's data and acts for nobody), and nothing is issued as that
// installation acting for itself.
func TestAModulePageHoldsNoStandingAuthority(t *testing.T) {
	h := newHarness(t)
	selecting := pageModule(1, true)
	selecting.InstallationRole = "viewer"
	if _, err := h.svc.ApplyModule(h.ctx, selecting); err != nil {
		t.Fatal(err)
	}
	inst := h.pagesAt(acme)
	if inst.AgentRole != "" || inst.InstalledBy != "" {
		t.Fatalf("a module page's installation holds standing authority: %+v", inst)
	}
	_, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "pages"}, inst.ID, authority.IssueRequest{Audience: "pages"})
	refused(t, err, "installation issuance requires the installed solution's workload")
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

// An installation made by composition was never approved, so a delivery
// that turns its module page into a solution declaring a governing scope
// governs nothing there: no administrator has seen who would manage its
// sources. Only an installation someone installed as a solution governs.
func TestACompositionInstallationGovernsNoSourceAfterItsTargetBecomesASolution(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	solution := pageModule(2, true)
	solution.Kind, solution.OwnerAware = domain.KindSolution, true
	solution.InstallationRole = ""
	solution.SourceGovernance = []*basev0.WorkScopeV1{sc("pages.note", "write")}
	if _, err := h.svc.ApplyModule(h.ctx, solution); err != nil {
		t.Fatalf("the kind change is refused (which would close this path too; update the test): %v", err)
	}
	m, err := h.svc.ApprovedDeclaration(h.ctx, h.pagesAt(acme))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.SourceGovernance) != 0 {
		t.Fatalf("a composition installation governs by %v, which no administrator approved", m.SourceGovernance)
	}
	// An administrator's review of the promoted installation approves it.
	if _, err := h.svc.Install(h.ctx, h.admin(acme), acme, "pages", "viewer", "remi", h.approval(acme, "pages"), nil); err != nil {
		t.Fatal(err)
	}
	reviewed := h.pagesAt(acme)
	if reviewed.Consent.OperationID == "" || reviewed.Consent.Generation != 2 {
		t.Fatalf("the review recorded no consent at generation 2: %+v", reviewed.Consent)
	}
	if m, err = h.svc.ApprovedDeclaration(h.ctx, reviewed); err != nil || len(m.SourceGovernance) != 1 {
		t.Fatalf("after its review the promoted installation governs by %v (%v)", m.SourceGovernance, err)
	}
}
