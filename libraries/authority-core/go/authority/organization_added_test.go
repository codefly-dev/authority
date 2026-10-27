package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// An organization created after the modules were delivered holds each of
// them as an organization that existed then does; a retired installation
// stays retired, and asking twice changes nothing.
func TestAnOrganizationAddedLaterHoldsEveryComposedModule(t *testing.T) {
	h := newHarness(t)
	const initech = "initech"
	h.store.PutOrganization(domain.Organization{ID: initech, Name: initech})
	h.store.PutPerson(domain.Person{ID: "ivy", Organization: initech})
	h.store.PutOrgRole(domain.OrgRole{Organization: initech, Name: "reader", Scopes: []domain.RoleScope{{Kind: kind, Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "ivy", Organization: initech, Roles: []string{"reader"}})
	ivy := authority.Person{ID: "ivy", Organization: initech, SessionID: "s-ivy"}
	_, err := h.svc.IssueForPerson(h.ctx, ivy, authority.IssueRequest{Audience: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "read")}})
	code(t, err, domain.Precondition)

	ids, err := h.svc.OrganizationAdded(h.ctx, initech)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 { // store and legacy-store; solutions are installed explicitly
		t.Fatalf("module installations %v", ids)
	}
	if _, err := h.svc.IssueForPerson(h.ctx, ivy, authority.IssueRequest{Audience: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "read")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UninstallAsHost(h.ctx, initech, authority.StableInstallationID(initech, "store")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.OrganizationAdded(h.ctx, initech); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.IssueForPerson(h.ctx, ivy, authority.IssueRequest{Audience: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "read")}})
	code(t, err, domain.Precondition)
	_, err = h.svc.OrganizationAdded(h.ctx, "nobody")
	code(t, err, domain.NotFound)

	// Reconciling every organization holds what is missing and nothing more.
	const hooli = "hooli"
	h.store.PutOrganization(domain.Organization{ID: hooli, Name: hooli})
	if err := h.svc.ReconcileOrganizations(h.ctx); err != nil {
		t.Fatal(err)
	}
	ids, err = h.svc.OrganizationAdded(h.ctx, hooli)
	if err != nil || len(ids) != 2 {
		t.Fatalf("reconciled module installations %v %v", ids, err)
	}
	_, err = h.svc.IssueForPerson(h.ctx, ivy, authority.IssueRequest{Audience: "store", Scopes: []*basev0.WorkScopeV1{sc(kind, "read")}})
	code(t, err, domain.Precondition)
}

// The host's own setup grants a role as the organization's administrator
// would: on an active installation of that organization, a declared role, to
// a member or a team of it.
func TestTheHostGrantsARoleAsTheAdministratorWould(t *testing.T) {
	h := newHarness(t)
	inst := h.inst(acme, "a").ID
	for _, tc := range []struct {
		name string
		r    authority.RoleRequest
		code domain.Code
	}{
		{"another organization's installation", authority.RoleRequest{Organization: globex, InstallationID: inst, Role: "viewer", PersonID: "omar"}, domain.Denied},
		{"an undeclared role", authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "owner", PersonID: "maya"}, domain.NotFound},
		{"no subject", authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer"}, domain.Invalid},
		{"a person of another organization", authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "omar"}, domain.Denied},
		{"a team of another organization", authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", TeamID: "ops"}, domain.Denied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.GrantRoleAsHost(h.ctx, tc.r)
			code(t, err, tc.code)
		})
	}
	if _, err := h.svc.GrantRoleAsHost(h.ctx, authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", PersonID: "maya"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.root("maya", "a"); err != nil {
		t.Fatalf("the granted role is held: %v", err)
	}
	if _, err := h.svc.GrantRoleAsHost(h.ctx, authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", TeamID: "team"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.root("tam", "a"); err != nil {
		t.Fatalf("the team's role is held: %v", err)
	}
}

func TestAComposedModuleReadsAsDelivered(t *testing.T) {
	h := newHarness(t)
	m, err := h.svc.Composed(h.ctx, "a")
	if err != nil || m.Principal != "a" || m.Kind != domain.KindSolution || len(m.Roles) != 4 {
		t.Fatalf("composed %+v %v", m, err)
	}
	_, err = h.svc.Composed(h.ctx, "absent")
	code(t, err, domain.NotFound)
}
