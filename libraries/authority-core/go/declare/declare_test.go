package declare_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/declare"
	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
	"github.com/stretchr/testify/require"
)

// composed is a fixture's composition: the class it is delivered to and
// its configurations, group by group.
type composed struct {
	Class  string                       `json:"class"`
	Values map[string]map[string]string `json:"values"`
}

func (c composed) infos() []*basev1.ConfigurationInformation {
	var out []*basev1.ConfigurationInformation
	for _, group := range slices.Sorted(maps.Keys(c.Values)) {
		info := &basev1.ConfigurationInformation{Name: group}
		for _, key := range slices.Sorted(maps.Keys(c.Values[group])) {
			info.ConfigurationValues = append(info.ConfigurationValues, &basev1.ConfigurationValue{Key: key, Value: c.Values[group][key]})
		}
		out = append(out, info)
	}
	return out
}

// TestDeclareRendersWhatTheCLIRendered holds the render to the CLI's own output
// before the render moved to core and then here, with the authority's
// document (core v0.19.31's solutionhost.Declare, moved byte-identical). Each testdata/declare/<case>/
// declaration.golden.json was written by the CLI at 68630378 (the parent of the
// commit that deleted its copy): its moduleAuthority lines and its
// ScopeCeilings, Roles, OwnerAware, SharedKinds and InstallationDeclaration
// readers, on the same contract and composition. Six cases: a solution with
// every part; a module with no roles; a role through an optional binding left
// out; self-addressed bindings, an audience list with a kind per audience and
// a resource_kind slot; a lookup with binding-key and kind slots, a headless
// binding at a later revision and a production class; a role scope on a
// consumed kind with an installation role and a staging class.
//
// The goldens are FROZEN: the code that wrote them is deleted, so they cannot
// be regenerated. A change to one is a change to what every module delivers
// its host, reviewed as a contract change, never refreshed to make this pass.
//
// One reviewed change since: a role's scope on a kind another module serves
// (solution and roles-no-owner-shared, store.item) is carried in the role's
// audiences, under the audience core resolves it at, where the CLI carried it
// in the role's scopes, held at every audience serving the kind.
func TestDeclareRendersWhatTheCLIRendered(t *testing.T) {
	cases, err := os.ReadDir(filepath.Join("testdata", "declare"))
	require.NoError(t, err)
	require.NotEmpty(t, cases)
	for _, entry := range cases {
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join("testdata", "declare", entry.Name())
			raw, err := os.ReadFile(filepath.Join(dir, "composition.json"))
			require.NoError(t, err)
			var c composed
			require.NoError(t, json.Unmarshal(raw, &c))
			declaration, _, err := declare.Module(dir, "", nil, solutionhost.Resolver(c.infos(), c.Class, nil))
			require.NoError(t, err)
			got, err := json.MarshalIndent(declaration, "", "  ")
			require.NoError(t, err)
			want, err := os.ReadFile(filepath.Join(dir, "declaration.golden.json"))
			require.NoError(t, err)
			require.JSONEq(t, string(want), string(got))
		})
	}
}

func TestDeclareModuleRefusesWhatTheRenderRefuses(t *testing.T) {
	resolve := solutionhost.Resolver(composed{Values: map[string]map[string]string{"ledger": {"store-audience": "store"}}}.infos(), "", nil)
	t.Run("a principal other than the module's name", func(t *testing.T) {
		_, _, err := declare.Module(filepath.Join("testdata", "declare", "module"), "journal", nil, resolve)
		require.ErrorContains(t, err, `module journal publishes a contract whose principal is "ledger"`)
	})
	t.Run("the retired roles declaration", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, solutionhost.RetiredRolesFileName), []byte("roles: []\n"), 0o600))
		_, _, err := declare.Module(dir, "", nil, resolve)
		require.ErrorContains(t, err, "roles.codefly.yaml is no longer read")
	})
	t.Run("no contract declares nothing", func(t *testing.T) {
		declaration, resolved, err := declare.Module(t.TempDir(), "ledger", nil, resolve)
		require.NoError(t, err)
		require.Nil(t, declaration)
		require.Nil(t, resolved)
	})
	t.Run("a slot the composition does not fill", func(t *testing.T) {
		_, _, err := declare.Module(filepath.Join("testdata", "declare", "module"), "ledger", nil, solutionhost.Resolver(nil, "", nil))
		require.ErrorIs(t, err, modulecontract.ErrUnresolvedSlot)
	})
}

// Every record is handed to core's resolution as supplied: a key supplied
// public and secret resolves as the secret, which core refuses as a slot value.
func TestModuleRefusesASecretSlotValue(t *testing.T) {
	infos := []*basev1.ConfigurationInformation{
		{Name: "ledger", ConfigurationValues: []*basev1.ConfigurationValue{{Key: "store-audience", Value: "store"}}},
		{Name: "ledger", ConfigurationValues: []*basev1.ConfigurationValue{{Key: "store-audience", Value: "store", Secret: true}}},
	}
	_, _, err := declare.Module(filepath.Join("testdata", "declare", "module"), "ledger", nil, solutionhost.Resolver(infos, "", nil))
	require.ErrorIs(t, err, modulecontract.ErrSecretSlot)
}

// A composed solution's request (its api.consumes, core's ConsumptionContract)
// is rendered in place of an own contract the module does not publish.
func TestDeclareModuleRendersTheCallersRequest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "declare", "module", modulecontract.FileName))
	require.NoError(t, err)
	request, err := modulecontract.Parse(raw)
	require.NoError(t, err)
	resolve := solutionhost.Resolver(composed{Values: map[string]map[string]string{"ledger": {"store-audience": "store"}}}.infos(), "", nil)
	declaration, _, err := declare.Module(t.TempDir(), "ledger", request, resolve)
	require.NoError(t, err)
	require.Equal(t, "ledger", declaration.Authority.Principal)
	require.Equal(t, []solutionhost.AuthorityBinding{{ID: "store", Audience: "store", Operations: map[string][]string{"invoke": {"store.item:read"}}}}, declaration.Authority.Bindings)
}

// published answers a module's bundles from its contract, as a renderer
// reading the composed modules does; no call is ever asked of it.
type published map[string]*modulecontract.Contract

func (p published) Bundle(module, name string) ([]modulecontract.CeilingScope, error) {
	return p[module].Bundle(name)
}

func (published) Requires(string, string) ([]string, error) { return nil, os.ErrNotExist }

// A role that includes a bundle another module publishes is declared with the
// bundle's scopes granted beside its own: the declaration a host receives
// carries what the role grants, never only the include's name. A scope the
// bundle reaches through its module is declared through the unit's binding
// to that module.
func TestADeclaredRoleCarriesTheBundlesItIncludes(t *testing.T) {
	agent, err := modulecontract.Parse([]byte(`schema: codefly/module-contract/v1
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
`))
	require.NoError(t, err)
	unit, err := modulecontract.Parse([]byte(`schema: codefly/module-contract/v1
principal: ledger
owner_aware: true
namespaces: []
queues: []
scope_ceilings: [{resource_kind: ledger.page, actions: [read]}]
roles:
  - name: admin
    includes: [{module: store, bundle: browse}]
    scopes: [{resource_kind: ledger.page, actions: [read]}]
  - name: user
    scopes: [{resource_kind: ledger.page, actions: [read]}]
bindings:
  - id: store
    operations: [invoke]
    audience: {from: ledger/store-audience}
    scope_ceiling:
      invoke: [{resource_kind: store.item, actions: [read]}]
destinations: []
`))
	require.NoError(t, err)
	resolve := solutionhost.Resolver(composed{Values: map[string]map[string]string{"ledger": {"store-audience": "store"}}}.infos(), "", published{"store": agent})
	declaration, _, err := declare.Module(t.TempDir(), "ledger", unit, resolve)
	require.NoError(t, err)
	admin := declaration.Document.Roles[0]
	// The bundle's direct scope is on the store's kind: held at the store,
	// the audience of the binding that carries it, and nowhere else.
	require.Equal(t, []declare.DeclaredScope{{ResourceKind: "ledger.page", Actions: []string{"read"}}}, admin.Scopes)
	require.Equal(t, []declare.RoleAudience{{Audience: "store", Scopes: []declare.DeclaredScope{{ResourceKind: "store.item", Actions: []string{"read"}}}}}, admin.Audiences)
	require.Equal(t, []declare.RoleThrough{{Binding: "store", Scopes: []declare.DeclaredScope{{ResourceKind: "notes", Actions: []string{"read"}}}}}, admin.Through)
}

func TestRenderPreservesAnAudienceAddressedGrant(t *testing.T) {
	dir := filepath.Join("testdata", "declare", "roles-no-owner-shared")
	unit, err := modulecontract.Load(dir)
	require.NoError(t, err)
	unit.Roles[1].Scopes = nil
	unit.Roles[1].Bindings = []modulecontract.RoleBinding{{Binding: "store", Operation: "invoke"}}
	resolve := solutionhost.Resolver(composed{Values: map[string]map[string]string{"board": {"store-audience": "records"}}}.infos(), "", nil)
	resolved, err := resolve(unit)
	require.NoError(t, err)
	require.Equal(t, []string{"store.item:read", "store.item:write"}, resolved.Roles[1].Grants["records"])
	declaration, err := declare.From(unit, resolved)
	require.NoError(t, err)
	role := declaration.Document.Roles[1]
	require.Empty(t, role.Scopes)
	require.Equal(t, []declare.RoleAudience{{Audience: "records", Scopes: []declare.DeclaredScope{{ResourceKind: "store.item", Actions: []string{"read", "write"}}}}}, role.Audiences)
}
