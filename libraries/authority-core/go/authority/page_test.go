package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
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
	ledgerPage(t, h)
	h.grant("pages", "viewer", "maya")

	t.Run("a module page's viewer reaches the ledger through the page's binding, read alone", func(t *testing.T) {
		got := h.must(h.page("maya", "pages", "ledger"))
		exactly(t, got, ledgerKind, "", []string{"read"})
		if chain := got.Context.GetActorChain(); len(chain) == 0 || chain[len(chain)-1].GetPrincipalId() != "pages" {
			t.Fatalf("the page's target is the actor of the hop: %v", chain)
		}
		if err := h.check(got); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("and the owner-aware store's kind as the page installation's data (RBAC-1)", func(t *testing.T) {
		exactly(t, h.must(h.page("maya", "pages", "store")), kind, h.principal(acme, "pages"), []string{"read"})
	})
	t.Run("and is refused what the role lacks, or with no role", func(t *testing.T) {
		_, err := h.page("maya", "pages", "ledger", sc(ledgerKind, "write"))
		refused(t, err, `a child widens what its owner holds through binding "ledger"`)
		_, err = h.page("remi", "pages", "ledger")
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

// The page hop is of kind page, the person present; a module's hop over the
// same binding is a service's, and nothing but IssueForPage mints the first.
// Consent in person admits the page hop alone: not a module's hop, not a
// page hop with a further hop after it.
func TestAPageHopIsThePersonPresent(t *testing.T) {
	h := newHarness(t)
	ledgerPage(t, h)
	h.grant("pages", "viewer", "maya")
	kindOf := func(i authority.Issued) []string {
		var kinds []string
		for _, a := range i.Context.GetActorChain() {
			kinds = append(kinds, a.GetPrincipalKind())
		}
		return kinds
	}
	viaPage := h.must(h.page("maya", "pages", "ledger"))
	if got := kindOf(viaPage); len(got) != 1 || got[0] != decide.PageActor || !decide.PresentThroughPage(viaPage.Context.GetActorChain()) {
		t.Fatalf("the page hop's actors are %v", got)
	}
	viaModule := h.must(h.through("maya", "pages", "ledger"))
	if got := kindOf(viaModule); len(got) != 1 || got[0] != "service" || decide.PresentThroughPage(viaModule.Context.GetActorChain()) {
		t.Fatalf("a module's hop over the same binding is %v", got)
	}
	// The ledger hopping on onward from the page hop: the chain grows, and
	// is no longer the person present.
	onward, err := h.svc.IssueChild(h.ctx, viaPage.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self"})
	if err != nil {
		t.Fatal(err)
	}
	if got := kindOf(onward); len(got) != 2 || got[0] != decide.PageActor || got[1] != "service" || decide.PresentThroughPage(onward.Context.GetActorChain()) {
		t.Fatalf("a hop after the page hop is %v", got)
	}
}
