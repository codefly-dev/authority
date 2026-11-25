package declare_test

import (
	"fmt"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/declare"
	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
	"github.com/stretchr/testify/require"
)

// composedModules answers the bundles and the calls of the modules a unit is
// composed with, as a renderer reading their contracts and method policies
// does.
type composedModules struct {
	bundles published
	calls   map[string]map[string][]string
}

func (c composedModules) Bundle(module, name string) ([]modulecontract.CeilingScope, error) {
	return c.bundles.Bundle(module, name)
}

func (c composedModules) Requires(audience, call string) ([]string, error) {
	required, ok := c.calls[audience][call]
	if !ok {
		return nil, fmt.Errorf("%s serves no %s", audience, call)
	}
	return required, nil
}

func contractOf(t *testing.T, text string) *modulecontract.Contract {
	t.Helper()
	contract, err := modulecontract.Parse([]byte(text))
	require.NoError(t, err)
	return contract
}

// rendered is unit's declaration against values, and the module a host
// composes from it (delivered.Declared), as a solution.
func rendered(t *testing.T, unit *modulecontract.Contract, values map[string]map[string]string, callees modulecontract.Callees) (*declare.Declaration, domain.Module) {
	t.Helper()
	declaration, _, err := declare.Module(t.TempDir(), unit.Principal, unit, solutionhost.Resolver(composed{Values: values}.infos(), "", callees))
	require.NoError(t, err)
	m, err := delivered.Declared(&solutionhost.ModuleManifest{Alias: unit.Principal, Kind: solutionhost.Kind(domain.KindSolution), Generation: 1}, declaration, nil)
	require.NoError(t, err)
	return declaration, m
}

func held(t *testing.T, m domain.Module, role, audience string) []*basev1.WorkScopeV1 {
	t.Helper()
	scopes, err := decide.RoleScopesAt(m, domain.Installation{ID: "i", PrincipalID: "owner"}, []string{role}, audience)
	require.NoError(t, err)
	return scope.Unowned(scopes)
}

func ws(kind string, actions ...string) *basev1.WorkScopeV1 {
	return &basev1.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

const storeContract = `schema: codefly/module-contract/v1
principal: store
namespaces: []
queues: []
scope_ceilings: [{resource_kind: store.item, actions: [read, write]}]
bindings: []
destinations: []
bundles:
  - name: browse
    scopes:
      - {resource_kind: store.item, actions: [read]}
      - {resource_kind: notes, actions: [read], through: store}
`

// However a role spells a grant on another module's kind (a scope of its own,
// a bundle it includes, a binding operation), the document addresses it to
// the audience core resolved it at: one entry per audience, sorted, each kind
// once. The role's scopes keep the unit's own kinds, its through scopes stay
// through, and what it grants on what the installation owns stays as
// declared. The host accepts the delivery and holds each grant at its callee
// alone.
func TestEveryGrantOnAnotherModulesKindIsAddressedToItsAudience(t *testing.T) {
	unit := contractOf(t, `schema: codefly/module-contract/v1
principal: ledger
owner_aware: true
namespaces: []
queues: []
scope_ceilings: [{resource_kind: ledger.page, actions: [read, write]}]
roles:
  - name: admin
    includes: [{module: store, bundle: browse}]
    scopes:
      - {resource_kind: ledger.page, actions: [read, write]}
      - {resource_kind: store.item, actions: [write]}
      - {resource_kind: archive.entry, actions: [read]}
    bindings: [{binding: archive, operation: lookup}]
    installation_owned_scopes: [{resource_kind: store.collection, actions: [read]}]
  - name: user
    includes: [{module: store, bundle: browse}]
    scopes: [{resource_kind: ledger.page, actions: [read]}]
bindings:
  - id: store
    operations: [invoke]
    audience: {from: ledger/store-audience}
    scope_ceiling:
      invoke:
        - {resource_kind: store.item, actions: [read, write]}
        - {resource_kind: store.collection, actions: [read]}
  - id: archive
    operations: [invoke, lookup]
    lookup: {method: header}
    audience: {from: ledger/archive-audience}
    scope_ceiling:
      invoke:
        - {resource_kind: archive.entry, actions: [read]}
        - {resource_kind: archive.index, actions: [read]}
      lookup: [{resource_kind: archive.index, actions: [read]}]
destinations: []
`)
	callees := composedModules{bundles: published{"store": contractOf(t, storeContract)}}
	declaration, m := rendered(t, unit, map[string]map[string]string{"ledger": {"store-audience": "store", "archive-audience": "archive"}}, callees)

	admin, user := declaration.Document.Roles[0], declaration.Document.Roles[1]
	require.Equal(t, declare.DeclaredRole{
		Name:   "admin",
		Scopes: []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read", "write"}}},
		Audiences: []declare.RoleAudience{
			{Audience: "archive", Scopes: []declare.DeclaredScope{{ResourceKind: "archive.entry", Actions: []string{"read"}}, {ResourceKind: "archive.index", Actions: []string{"read"}}}},
			{Audience: "store", Scopes: []declare.DeclaredScope{{ResourceKind: "store.item", Actions: []string{"read", "write"}}}},
		},
		InstallationOwnedScopes: []declare.DeclaredScope{{ResourceKind: "store.collection", Actions: []string{"read"}}},
		Through:                 []declare.RoleThrough{{Binding: "store", Scopes: []declare.DeclaredScope{{ResourceKind: "notes", Actions: []string{"read"}}}}},
	}, admin)
	require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read"}}}, user.Scopes)
	require.Equal(t, []declare.RoleAudience{{Audience: "store", Scopes: []declare.DeclaredScope{{ResourceKind: "store.item", Actions: []string{"read"}}}}}, user.Audiences)

	// The host accepts it: each audience grant is within the invoke and
	// lookup ceilings of a binding addressed to that audience.
	require.NoError(t, decide.ValidateModule(m))
	// Held at the callee, and at no other audience: not at the unit itself,
	// not at a sibling, not at a module that would serve the same kind.
	require.True(t, scope.Attenuates([]*basev1.WorkScopeV1{ws("store.item", "read", "write")}, held(t, m, "admin", "store")))
	require.True(t, scope.Attenuates([]*basev1.WorkScopeV1{ws("archive.entry", "read")}, held(t, m, "admin", "archive")))
	for _, audience := range []string{"ledger", "archive", "vault"} {
		require.False(t, scope.HoldsAction(held(t, m, "admin", audience), "store.item", "read"), audience)
		require.False(t, scope.HoldsAction(held(t, m, "user", audience), "store.item", "read"), audience)
	}
	require.False(t, scope.HoldsAction(held(t, m, "admin", "store"), "archive.entry", "read"))
	// Two renders spell the same bytes.
	again, _ := rendered(t, unit, map[string]map[string]string{"ledger": {"store-audience": "store", "archive-audience": "archive"}}, callees)
	require.Equal(t, declaration, again)
}

// A binding over a list of audiences is delivered once per audience, under
// its audience id, and names the calls it makes: a scope the role spells out
// is held at the one audience whose calls declare it, and the host finds the
// binding addressed there to hold it to.
func TestAScopeIsAddressedToTheOneListedAudienceThatDeclaresIt(t *testing.T) {
	unit := contractOf(t, `schema: codefly/module-contract/v1
principal: desk
owner_aware: true
namespaces: []
queues: []
scope_ceilings: [{resource_kind: desk.page, actions: [read]}]
roles:
  - name: admin
    scopes:
      - {resource_kind: desk.page, actions: [read]}
      - {resource_kind: robin.intents, actions: [read]}
bindings:
  - id: review
    operations: [invoke]
    audiences: {from: desk/review-audiences}
    calls:
      invoke: ["/review.v1.Review/Read"]
destinations: []
`)
	callees := composedModules{calls: map[string]map[string][]string{
		"robin":     {"/review.v1.Review/Read": {"robin.intents:read"}},
		"documents": {"/review.v1.Review/Read": {"documents:read"}},
	}}
	declaration, m := rendered(t, unit, map[string]map[string]string{"desk": {"review-audiences": "robin,documents"}}, callees)
	admin := declaration.Document.Roles[0]
	require.Equal(t, []declare.DeclaredScope{{ResourceKind: "desk.page", Actions: []string{"read"}}}, admin.Scopes)
	require.Equal(t, []declare.RoleAudience{{Audience: "robin", Scopes: []declare.DeclaredScope{{ResourceKind: "robin.intents", Actions: []string{"read"}}}}}, admin.Audiences)
	require.Contains(t, m.Bindings, modulecontract.AudienceBindingID("review", "robin"))
	require.NoError(t, decide.ValidateModule(m))
	require.True(t, scope.HoldsAction(held(t, m, "admin", "robin"), "robin.intents", "read"))
	require.False(t, scope.HoldsAction(held(t, m, "admin", "documents"), "robin.intents", "read"))
}

// A scope core addresses to no audience stays in the role's scopes exactly as
// declared, so the host decides it as it always has: nothing is dropped by
// the render.
func TestAScopeNoAudienceUnderwritesStaysAsDeclared(t *testing.T) {
	const head = `schema: codefly/module-contract/v1
principal: ledger
owner_aware: true
namespaces: []
queues: []
scope_ceilings: [{resource_kind: ledger.page, actions: [read]}]
`
	values := map[string]map[string]string{"ledger": {"store-audience": "store", "store-resource-kind": "store.item"}}
	t.Run("a kind nothing delivered carries is refused by the host", func(t *testing.T) {
		declaration, m := rendered(t, contractOf(t, head+`roles:
  - name: admin
    scopes:
      - {resource_kind: ledger.page, actions: [read]}
      - {resource_kind: vault.secret, actions: [read]}
bindings: []
destinations: []
`), values, nil)
		require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read"}}, {ResourceKind: "vault.secret", Actions: []string{"read"}}}, declaration.Document.Roles[0].Scopes)
		require.Empty(t, declaration.Document.Roles[0].Audiences)
		require.ErrorContains(t, decide.ValidateModule(m), "grants beyond what ledger serves or explicitly consumes")
	})
	t.Run("an action of the unit's own kind beyond its ceiling is refused by the host", func(t *testing.T) {
		declaration, m := rendered(t, contractOf(t, head+`roles:
  - name: admin
    scopes: [{resource_kind: ledger.page, actions: [read, purge]}]
bindings: []
destinations: []
`), values, nil)
		require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read", "purge"}}}, declaration.Document.Roles[0].Scopes)
		require.ErrorContains(t, decide.ValidateModule(m), "grants beyond what ledger serves or explicitly consumes")
	})
	t.Run("a kind only an optional binding left out carries is refused by the host, and a grant of that binding is left out with it", func(t *testing.T) {
		declaration, m := rendered(t, contractOf(t, head+`roles:
  - name: admin
    scopes:
      - {resource_kind: ledger.page, actions: [read]}
      - {resource_kind: archive.entry, actions: [read]}
  - name: user
    scopes: [{resource_kind: ledger.page, actions: [read]}]
    bindings: [{binding: archive, operation: invoke}]
bindings:
  - id: archive
    optional: true
    operations: [invoke]
    audience: {from: ledger/archive-audience}
    scope_ceiling:
      invoke: [{resource_kind: archive.entry, actions: [read]}]
destinations: []
`), values, nil)
		admin, user := declaration.Document.Roles[0], declaration.Document.Roles[1]
		require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read"}}, {ResourceKind: "archive.entry", Actions: []string{"read"}}}, admin.Scopes)
		require.Empty(t, admin.Audiences)
		require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read"}}}, user.Scopes)
		require.Empty(t, user.Audiences)
		require.ErrorContains(t, decide.ValidateModule(m), `role "admin" of ledger grants beyond`)
	})
	// A binding whose ceiling is bare actions on a resource-kind slot names
	// no kind, so core addresses a role scope of that kind nowhere: it stays
	// a scope held at every audience, as before this render addressed
	// anything. The role names the binding (bindings) to have it addressed.
	t.Run("a kind a binding carries as bare actions stays held at every audience", func(t *testing.T) {
		unit := contractOf(t, head+`roles:
  - name: admin
    scopes:
      - {resource_kind: ledger.page, actions: [read]}
      - {resource_kind: store.item, actions: [read]}
bindings:
  - id: store
    operations: [invoke]
    audience: {from: ledger/store-audience}
    resource_kind: {from: ledger/store-resource-kind}
    scope_ceiling:
      invoke: [read]
destinations: []
`)
		declaration, m := rendered(t, unit, values, nil)
		require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read"}}, {ResourceKind: "store.item", Actions: []string{"read"}}}, declaration.Document.Roles[0].Scopes)
		require.Empty(t, declaration.Document.Roles[0].Audiences)
		require.NoError(t, decide.ValidateModule(m))
		require.True(t, scope.HoldsAction(held(t, m, "admin", "vault"), "store.item", "read"))

		unit.Roles[0].Scopes = unit.Roles[0].Scopes[:1]
		unit.Roles[0].Bindings = []modulecontract.RoleBinding{{Binding: "store", Operation: "invoke"}}
		declaration, m = rendered(t, unit, values, nil)
		require.Equal(t, []declare.RoleAudience{{Audience: "store", Scopes: []declare.DeclaredScope{{ResourceKind: "store.item", Actions: []string{"read"}}}}}, declaration.Document.Roles[0].Audiences)
		require.NoError(t, decide.ValidateModule(m))
		require.False(t, scope.HoldsAction(held(t, m, "admin", "vault"), "store.item", "read"))
	})
}

// A kind the unit serves is held at the unit, and so is one a binding
// addressed to the unit itself carries: neither is an audience grant.
func TestAScopeOnTheUnitsOwnKindStaysInItsScopes(t *testing.T) {
	declaration, m := rendered(t, contractOf(t, `schema: codefly/module-contract/v1
principal: ledger
owner_aware: true
namespaces: []
queues: []
scope_ceilings: [{resource_kind: ledger.page, actions: [read, write]}]
roles:
  - name: admin
    scopes: [{resource_kind: ledger.page, actions: [read, write]}]
bindings:
  - id: pages
    operations: [invoke]
    audience: {self: true}
    scope_ceiling:
      invoke: [{resource_kind: ledger.page, actions: [read]}]
destinations: []
`), nil, nil)
	require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read", "write"}}}, declaration.Document.Roles[0].Scopes)
	require.Empty(t, declaration.Document.Roles[0].Audiences)
	require.NoError(t, decide.ValidateModule(m))
}
