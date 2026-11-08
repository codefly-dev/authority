package decide_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

var closureRead = []*basev0.WorkScopeV1{{ResourceKind: "x", Actions: []string{"read"}}}

func closureBinding(audience string) domain.Binding {
	return domain.Binding{ID: audience, Audience: audience, InvokeScopes: closureRead}
}

// Principals differ from names: the closure resolves what a binding or an
// edge names, a principal, to the module's name.
func closureModules() []domain.Module {
	return []domain.Module{
		{Name: "page", Principal: "page-p", Kind: domain.KindModule, Page: true, Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: closureRead},
			Bindings:         map[string]domain.Binding{"records": closureBinding("records-p")},
			EdgeDependencies: []domain.EdgeDependency{{Module: "robin-p", Presence: "required"}, {Module: "tracing-p", Presence: decide.EdgeOptional}}},
		{Name: "records", Principal: "records-p", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"store": closureBinding("store-p"), "self": closureBinding("records-p")}},
		{Name: "store", Principal: "store-p", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"page": closureBinding("page-p")},
			EdgeDependencies: []domain.EdgeDependency{{Module: "annotations-p", Presence: decide.EdgeOptional}}},
		{Name: "robin", Principal: "robin-p", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"model": closureBinding("model-p")}},
		{Name: "model", Principal: "model-p", Kind: domain.KindModule},
		{Name: "tracing", Principal: "tracing-p", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"model": closureBinding("model-p")}},
		{Name: "annotations", Principal: "annotations-p", Kind: domain.KindModule},
		{Name: "wiki", Principal: "wiki-p", Kind: domain.KindSolution, Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: closureRead},
			Bindings: map[string]domain.Binding{"records": closureBinding("records-p"), "page": closureBinding("page-p")}},
	}
}

func named(modules []domain.Module, name string) domain.Module {
	for _, m := range modules {
		if m.Name == name {
			return m
		}
	}
	return domain.Module{}
}

// The closure of a target is every module without roles it reaches through
// bindings and required edges, transitively, by principal; a role-gated
// target reached is chosen on its own review and neither listed nor walked
// through; the target itself is never listed; optional edges, the target's
// and its closure's, are answered apart and never walked.
func TestClosureReachesModulesWithoutRolesTransitively(t *testing.T) {
	modules := closureModules()
	for _, tc := range []struct {
		target         string
		want, optional []string
	}{
		{"page", []string{"model", "records", "robin", "store"}, []string{"annotations", "tracing"}},
		{"wiki", []string{"records", "store"}, []string{"annotations"}},
		{"records", []string{"store"}, []string{"annotations"}},
		{"model", nil, nil},
	} {
		got, optional, err := decide.Closure(named(modules, tc.target), modules)
		if err != nil || !slices.Equal(got, tc.want) || !slices.Equal(optional, tc.optional) {
			t.Errorf("closure of %s is %v, optional %v (%v); want %v, %v", tc.target, got, optional, err, tc.want, tc.optional)
		}
	}
}

// A binding audience or a required edge that is not composed is an error
// naming it, at the target and down its closure; an optional edge that is
// not composed is answered by its principal, not an error.
func TestClosureRefusesWhatIsNotComposed(t *testing.T) {
	modules := closureModules()
	t.Run("a binding audience of the target", func(t *testing.T) {
		m := named(modules, "page")
		m.Bindings = map[string]domain.Binding{"gone": closureBinding("gone-p")}
		_, _, err := decide.Closure(m, modules)
		if err == nil || !strings.Contains(err.Error(), `page binding gone names "gone-p"`) {
			t.Fatalf("want a refusal naming the binding, got %v", err)
		}
	})
	t.Run("a required edge of the target", func(t *testing.T) {
		m := named(modules, "page")
		m.EdgeDependencies = []domain.EdgeDependency{{Module: "gone-p", Presence: "required"}}
		_, _, err := decide.Closure(m, modules)
		if err == nil || !strings.Contains(err.Error(), `page edge dependency (required) names "gone-p"`) {
			t.Fatalf("want a refusal naming the edge, got %v", err)
		}
	})
	t.Run("a binding audience down the closure", func(t *testing.T) {
		broken := slices.Clone(modules)
		for i := range broken {
			if broken[i].Name == "store" {
				broken[i].Bindings = map[string]domain.Binding{"gone": closureBinding("gone-p")}
			}
		}
		_, _, err := decide.Closure(named(broken, "page"), broken)
		if err == nil || !strings.Contains(err.Error(), "store binding gone") {
			t.Fatalf("want a refusal naming the store's binding, got %v", err)
		}
	})
	t.Run("an optional edge that is not composed", func(t *testing.T) {
		m := named(modules, "model")
		m.EdgeDependencies = []domain.EdgeDependency{{Module: "gone-p", Presence: decide.EdgeOptional}}
		got, optional, err := decide.Closure(m, modules)
		if err != nil || len(got) != 0 || !slices.Equal(optional, []string{"gone-p"}) {
			t.Fatalf("closure %v, optional %v, %v", got, optional, err)
		}
	})
}
