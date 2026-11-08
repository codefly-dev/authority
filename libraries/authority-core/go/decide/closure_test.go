package decide_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The closure of a target is every module without roles it reaches through
// bindings and edge dependencies, transitively; a role-gated target reached
// is chosen on its own review and neither listed nor walked through; the
// target itself is never listed.
func TestClosureReachesModulesWithoutRolesTransitively(t *testing.T) {
	read := []*basev0.WorkScopeV1{{ResourceKind: "x", Actions: []string{"read"}}}
	binding := func(audience string) domain.Binding {
		return domain.Binding{ID: audience, Audience: audience, InvokeScopes: read}
	}
	modules := []domain.Module{
		{Name: "page", Principal: "page-principal", Kind: domain.KindModule, Page: true, Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: read},
			Bindings: map[string]domain.Binding{"records": binding("records")}, EdgeDependencies: []domain.EdgeDependency{{Module: "robin-principal", Presence: "required"}}},
		{Name: "records", Principal: "records-principal", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"store": binding("store"), "self": binding("records")}},
		{Name: "store", Principal: "store-principal", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"page": binding("page")}},
		{Name: "robin", Principal: "robin-principal", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"model": binding("model")}},
		{Name: "model", Principal: "model-principal", Kind: domain.KindModule},
		{Name: "wiki", Principal: "wiki-principal", Kind: domain.KindSolution, Roles: map[string][]*basev0.WorkScopeV1{domain.InstallerRole: read},
			Bindings: map[string]domain.Binding{"records": binding("records"), "page": binding("page"), "tracing": binding("tracing")}},
		{Name: "tracing", Principal: "tracing-principal", Kind: domain.KindModule, Bindings: map[string]domain.Binding{"wiki": binding("wiki")}},
	}
	for _, tc := range []struct {
		target string
		want   []string
	}{
		{"page", []string{"model", "records", "robin", "store"}},
		{"wiki", []string{"records", "store", "tracing"}},
		{"records", []string{"store"}},
		{"model", nil},
	} {
		var m domain.Module
		for _, c := range modules {
			if c.Name == tc.target {
				m = c
			}
		}
		if got := decide.Closure(m, modules); !slices.Equal(got, tc.want) {
			t.Errorf("closure of %s is %v, want %v", tc.target, got, tc.want)
		}
	}
}
