package authority_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A child is the owner's current grants intersected with the binding it is
// issued through: a scope the parent holds outside the binding never reaches
// the child, whatever the parent carried (rule A, r122 on runtime #311).
func TestAChildHoldsOnlyWhatTheBindingAndTheOwnersGrantsShare(t *testing.T) {
	h := newHarness(t)
	page := domain.Module{Name: "page", Principal: "page", Kind: domain.KindModule, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{sc("page.entry", "read"), sc(kind, "read", "write"), sc("profiles", "read")},
		Bindings: map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}}}
	if _, err := h.svc.ApplyModule(h.ctx, page); err != nil {
		t.Fatal(err)
	}
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "wide", Scopes: []domain.RoleScope{
		{Kind: "page.entry", Actions: []string{"read"}}, {Kind: kind, Actions: []string{"read", "write"}}, {Kind: "profiles", Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "wren", Organization: acme, Roles: []string{"wide"}})

	parent := h.must(h.root("wren", "page"))
	if kinds := kindsOf(effective(parent)); !slices.Equal(kinds, []string{kind, "page.entry", "profiles"}) {
		t.Fatalf("the parent holds %v; the test needs scopes outside the binding", kinds)
	}
	for name, ask := range map[string][]*basev0.WorkScopeV1{"everything held": nil, "the binding's kind": {sc(kind, "read", "write")}} {
		t.Run(name, func(t *testing.T) {
			child := h.must(h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "page"}, authority.IssueRequest{Binding: "store", Scopes: ask}))
			exactly(t, child, kind, "", []string{"read", "write"})
			verified, _, err := h.svc.Check(h.ctx, child.Token, "store")
			if err != nil {
				t.Fatal(err)
			}
			if kinds := kindsOf(verified.EffectiveScopes()); !slices.Equal(kinds, []string{kind}) {
				t.Fatalf("the checked child holds %v, want only %s", kinds, kind)
			}
		})
	}
	t.Run("a scope outside the binding", func(t *testing.T) {
		_, err := h.svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "page"}, authority.IssueRequest{Binding: "store", Scopes: []*basev0.WorkScopeV1{sc("profiles", "read")}})
		refused(t, err, "widens")
	})
}

func kindsOf(scopes []*basev0.WorkScopeV1) []string {
	var out []string
	for _, s := range scopes {
		if len(s.GetActions()) > 0 && !slices.Contains(out, s.GetResourceKind()) {
			out = append(out, s.GetResourceKind())
		}
	}
	slices.Sort(out)
	return out
}
