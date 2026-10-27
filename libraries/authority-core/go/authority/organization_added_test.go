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
}
