package decide_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func rsc(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

// approvedModule is the reviewed surface an administrator approved: a
// solution with two roles, an installation-owned role, a binding with the
// three scope lists, a required and an optional edge, no standing authority
// and two method policies.
func approvedModule() domain.Module {
	return domain.Module{Name: "a", Principal: "a", Kind: domain.KindSolution, Generation: 1, InstallationRole: domain.NoInstallationRole,
		ResourceKinds: []*basev0.WorkScopeV1{rsc("a.note", "read", "write")},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {rsc("a.note", "read", "write")},
			"viewer":             {rsc("a.note", "read")},
		},
		OwnedRoles: map[string][]*basev0.WorkScopeV1{"viewer": {rsc("store.item", "read")}},
		Bindings: map[string]domain.Binding{"store": {ID: "store", Audience: "store",
			InvokeScopes: []*basev0.WorkScopeV1{rsc("store.item", "read", "write")}, HeadlessScopes: []*basev0.WorkScopeV1{rsc("store.item", "read")}, LookupScopes: []*basev0.WorkScopeV1{rsc("store.item", "read")}}},
		EdgeDependencies: []domain.EdgeDependency{{Module: "robin", Presence: "required"}, {Module: "tracing", Presence: decide.EdgeOptional}},
		Methods: map[string]domain.MethodPolicy{
			"/a.Notes/Get":  {Requires: []*basev0.WorkScopeV1{rsc("a.note", "read")}},
			"/a.Notes/Put":  {Requires: []*basev0.WorkScopeV1{rsc("a.note", "write")}},
			"/a.Notes/Ping": {AnyCheckedCaller: true},
		}}
}

// Every clause of the reviewed surface widens by exactly one spelling, and
// nothing that narrows or stays is ever listed.
func TestWidensNamesEachClauseOfTheReviewedSurface(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*domain.Module)
		want   []string
	}{
		{"nothing changes", func(*domain.Module) {}, nil},
		{"kind", func(m *domain.Module) { m.Kind = domain.KindModule; m.Page = true }, []string{"kind solution is now module"}},
		{"role added", func(m *domain.Module) { m.Roles["editor"] = []*basev0.WorkScopeV1{rsc("a.note", "read")} }, []string{"role editor added"}},
		{"role reaches further", func(m *domain.Module) { m.Roles["viewer"] = []*basev0.WorkScopeV1{rsc("a.note", "read", "write")} }, []string{"role viewer reaches further"}},
		{"owned role added", func(m *domain.Module) { m.OwnedRoles["installer"] = []*basev0.WorkScopeV1{rsc("store.item", "read")} }, []string{"installation-owned role installer added"}},
		{"owned role reaches further", func(m *domain.Module) {
			m.OwnedRoles["viewer"] = []*basev0.WorkScopeV1{rsc("store.item", "read", "write")}
		}, []string{"installation-owned role viewer reaches further"}},
		{"binding added", func(m *domain.Module) {
			m.Bindings["model"] = domain.Binding{ID: "model", Audience: "model", InvokeScopes: []*basev0.WorkScopeV1{rsc("model.profiles", "read")}}
		}, []string{"binding model added"}},
		{"binding readdressed", func(m *domain.Module) { b := m.Bindings["store"]; b.Audience = "other-store"; m.Bindings["store"] = b }, []string{"binding store readdressed from store to other-store"}},
		{"binding invoke reaches further", func(m *domain.Module) {
			b := m.Bindings["store"]
			b.InvokeScopes = []*basev0.WorkScopeV1{rsc("store.item", "admin", "read", "write")}
			m.Bindings["store"] = b
		}, []string{"binding store reaches further"}},
		{"binding headless reaches further", func(m *domain.Module) {
			b := m.Bindings["store"]
			b.HeadlessScopes = []*basev0.WorkScopeV1{rsc("store.item", "read", "write")}
			m.Bindings["store"] = b
		}, []string{"binding store reaches further"}},
		{"binding lookup reaches further", func(m *domain.Module) {
			b := m.Bindings["store"]
			b.LookupScopes = []*basev0.WorkScopeV1{rsc("store.item", "read", "write")}
			m.Bindings["store"] = b
		}, []string{"binding store reaches further"}},
		{"edge added", func(m *domain.Module) {
			m.EdgeDependencies = append(m.EdgeDependencies, domain.EdgeDependency{Module: "model", Presence: "required"})
		}, []string{"edge dependency on model (required) added"}},
		{"edge made required", func(m *domain.Module) { m.EdgeDependencies[1].Presence = "required" }, []string{"edge dependency on tracing made required"}},
		{"selector asked", func(m *domain.Module) { m.InstallationRole = "viewer" }, []string{"installation role viewer asked"}},
		{"selector left to the installer", func(m *domain.Module) { m.InstallationRole = "" }, []string{"installation role left to the installer"}},
		{"method added", func(m *domain.Module) {
			m.Methods["/a.Notes/List"] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{rsc("a.note", "read")}}
		}, []string{"method /a.Notes/List added"}},
		{"method opened to any checked caller", func(m *domain.Module) { m.Methods["/a.Notes/Get"] = domain.MethodPolicy{AnyCheckedCaller: true} }, []string{"method /a.Notes/Get opened to any checked caller"}},
		{"method requires less", func(m *domain.Module) {
			m.Methods["/a.Notes/Put"] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{rsc("a.note", "read")}}
		}, []string{"method /a.Notes/Put requires less"}},
		{"two clauses, in review order", func(m *domain.Module) {
			m.Roles["editor"] = []*basev0.WorkScopeV1{rsc("a.note", "read")}
			m.Methods["/a.Notes/List"] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{rsc("a.note", "read")}}
		}, []string{"role editor added", "method /a.Notes/List added"}},
		// Narrowings and neutral changes ask nothing new.
		{"role dropped", func(m *domain.Module) { delete(m.Roles, "viewer"); delete(m.OwnedRoles, "viewer") }, nil},
		{"role scope cut", func(m *domain.Module) { m.Roles[domain.InstallerRole] = []*basev0.WorkScopeV1{rsc("a.note", "read")} }, nil},
		{"owned role dropped", func(m *domain.Module) { delete(m.OwnedRoles, "viewer") }, nil},
		{"binding dropped", func(m *domain.Module) { delete(m.Bindings, "store") }, nil},
		{"binding scopes cut", func(m *domain.Module) {
			b := m.Bindings["store"]
			b.InvokeScopes = []*basev0.WorkScopeV1{rsc("store.item", "read")}
			m.Bindings["store"] = b
		}, nil},
		{"edge dropped", func(m *domain.Module) { m.EdgeDependencies = m.EdgeDependencies[1:] }, nil},
		{"edge made optional", func(m *domain.Module) { m.EdgeDependencies[0].Presence = decide.EdgeOptional }, nil},
		{"selector to none from a role", func(m *domain.Module) { m.InstallationRole = domain.NoInstallationRole }, nil},
		{"method dropped", func(m *domain.Module) { delete(m.Methods, "/a.Notes/Put") }, nil},
		{"method requires more", func(m *domain.Module) {
			m.Methods["/a.Notes/Get"] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{rsc("a.note", "read", "write")}}
		}, nil},
		{"method closed to a role from any caller", func(m *domain.Module) {
			m.Methods["/a.Notes/Ping"] = domain.MethodPolicy{Requires: []*basev0.WorkScopeV1{rsc("a.note", "read")}}
		}, nil},
		{"served and owner-aware are not reviewed", func(m *domain.Module) {
			m.ResourceKinds = append(m.ResourceKinds, rsc("a.draft", "read"))
			m.OwnerAware = !m.OwnerAware
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			approved, next := approvedModule(), approvedModule()
			tc.change(&next)
			if got := decide.Widens(approved, next); !slices.Equal(got, tc.want) {
				t.Fatalf("widens %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("a wildcard action approved covers any action asked", func(t *testing.T) {
		approved, next := approvedModule(), approvedModule()
		approved.Roles["viewer"] = []*basev0.WorkScopeV1{rsc("a.note", "*")}
		next.Roles["viewer"] = []*basev0.WorkScopeV1{rsc("a.note", "read", "write", "publish")}
		if got := decide.Widens(approved, next); len(got) != 0 {
			t.Fatalf("an approved wildcard was widened by named actions: %v", got)
		}
	})
	t.Run("a selector change from a role to the installer's choice asks", func(t *testing.T) {
		approved, next := approvedModule(), approvedModule()
		approved.InstallationRole, next.InstallationRole = "viewer", ""
		if got := decide.Widens(approved, next); !slices.Equal(got, []string{"installation role left to the installer"}) {
			t.Fatalf("widens %v", got)
		}
	})
}
