package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func (h *harness) page(person, target, audience string, scopes ...*basev0.WorkScopeV1) (authority.Issued, error) {
	return h.svc.IssueForPage(h.ctx, h.person(person), target, authority.IssueRequest{Audience: audience, Scopes: scopes})
}

// One rule for every page: a call a page makes on the host's module edge to a
// module its target declares a binding to is issued through that binding,
// the person's role on the target cut to it; to a module its target declares
// no binding to, on the person's own access.
func TestAPagesCallGoesThroughItsTargetsBinding(t *testing.T) {
	h := newHarness(t)
	m := pageModule(1, true)
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}}
	m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{sc("pages.note", "read", "write"), sc(kind, "read", "write")}
	m.Roles["viewer"] = []*basev0.WorkScopeV1{sc("pages.note", "read"), sc(kind, "read")}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "viewer", "maya")

	t.Run("a module page's viewer reaches the store through the page's binding, read alone", func(t *testing.T) {
		got := h.must(h.page("maya", "pages", "store"))
		exactly(t, got, kind, "", []string{"read"})
		if chain := got.Context.GetActorChain(); len(chain) == 0 || chain[len(chain)-1].GetPrincipalId() != "pages" {
			t.Fatalf("the page's target is the actor of the hop: %v", chain)
		}
		if err := h.check(got); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("and is refused what the role lacks, or with no role", func(t *testing.T) {
		_, err := h.page("maya", "pages", "store", sc(kind, "write"))
		refused(t, err, `a child widens what its owner holds through binding "store"`)
		_, err = h.page("remi", "pages", "store")
		refused(t, err, "holds no role on pages")
	})
	t.Run("a module the page's target declares no binding to is on the person's own access", func(t *testing.T) {
		h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "legacy-reader", Scopes: []domain.RoleScope{{Kind: legacyKind, Actions: []string{"read"}}}})
		h.store.PutPerson(domain.Person{ID: "lea", Organization: acme, Roles: []string{"legacy-reader"}})
		exactly(t, h.must(h.page("lea", "pages", "legacy-store")), legacyKind, "", []string{"read"})
		_, err := h.page("maya", "pages", "legacy-store")
		refused(t, err, "the owner holds nothing at this audience")
	})
	t.Run("a solution's page goes through the solution's binding, as its backend does", func(t *testing.T) {
		h.grant("a", "viewer", "tal")
		want := h.must(h.through("tal", "a", "store"))
		got := h.must(h.page("tal", "a", "store"))
		if len(effective(got)) != len(effective(want)) || effective(got)[0].GetResourceOwnerId() != effective(want)[0].GetResourceOwnerId() {
			t.Fatalf("through the page %v, through the backend %v", effective(got), effective(want))
		}
	})
}
