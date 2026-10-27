package state_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

const head = "schema: codefly.dev/authority/fixture-composition/v1\n"

// fixtureOnly is a state holding the embedded fixture and one synthetic
// module, ledger, that the fixture never names.
func fixtureOnly(t *testing.T) *testkit.Kit {
	t.Helper()
	k := testkit.Bare(t)
	data, err := os.ReadFile(testkit.FixturePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := k.State.LoadFixture(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	ledger := state.Manifest{Name: "ledger", Principal: "ledger", Kind: "module", Generation: 1,
		Methods: map[string]state.MethodPolicy{
			"/ledger/Read":    {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "read")}},
			"/ledger/Write":   {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}},
			"/ledger/Approve": {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "approve")}},
		}}
	if _, err := k.State.ApplyManifest(ledger); err != nil {
		t.Fatal(err)
	}
	return k
}

// The embedded fixture grants nothing at a module; a composition grants the
// fixture's roles exactly what it names.
func TestCompositionGrantsFixtureRolesWhatItsModuleServes(t *testing.T) {
	k := fixtureOnly(t)
	for _, person := range []string{"maya", "remi", "alex", "zoe"} {
		if held, _ := k.PersonScopes(t, person, "ledger"); len(held) != 0 {
			t.Fatalf("the fixture alone grants %s %v at ledger", person, held)
		}
	}
	lines, err := k.State.ApplyComposition(context.Background(), []byte(head+`
roles:
  - organization: acme
    name: editor
    scopes:
      - {kind: ledger.entry, actions: [read, write]}
  - organization: acme
    name: admin
    scopes:
      - {kind: ledger.entry, actions: [approve]}
  - organization: acme
    name: viewer
    scopes:
      - kind: ledger.entry
        actions: [read]
        resources: [{prefix: "public-"}]
`))
	if err != nil || len(lines) != 3 {
		t.Fatalf("apply: %v %v", lines, err)
	}
	for person, scope := range map[string]*basev0.WorkScopeV1{
		"remi": testkit.Scope("ledger.entry", "read", "write"),
		"alex": testkit.Scope("ledger.entry", "approve"),
	} {
		held, err := k.PersonScopes(t, person, "ledger")
		if err != nil || !state.Attenuates([]*basev0.WorkScopeV1{scope}, held) {
			t.Errorf("%s holds %v at ledger (%v), want %v", person, held, err, scope)
		}
	}
	if held, _ := k.PersonScopes(t, "alex", "ledger"); state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}, held) {
		t.Error("a grant to the editor reached the admin")
	}
	if err := k.State.AdmitMethod("ledger", "/ledger/Approve", mustHeld(t, k, "remi")); err == nil {
		t.Error("the editor was admitted to the admin's method")
	}
	// The viewer's grant keeps its prefix: she is issued an id it matches and
	// refused one it does not, and an ask naming none carries none of it.
	grants, err := k.ResourceGrants(t, "maya", "ledger", "ledger.entry", "read", "public-1")
	if err != nil || len(grants) != 1 || grants[0].ID != "public-1" {
		t.Errorf("the viewer's grant keeps its resources: %v %v", grants, err)
	}
	if _, err := k.ResourceGrants(t, "maya", "ledger", "ledger.entry", "read", "private-1"); err == nil || !strings.Contains(err.Error(), "what the owner holds") {
		t.Errorf("the viewer's grant widened past its prefix: %v", err)
	}
	if _, err := k.ResourceGrants(t, "maya", "ledger", "ledger.entry", "read"); err == nil {
		t.Error("an empty ask carried the viewer's prefix as the whole kind")
	}
	// The fixture's own vocabulary stays.
	if scopes := k.State.RoleScopes("acme", "viewer"); !state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("console.identity", "read")}, scopes) {
		t.Errorf("the fixture's console grant was lost: %v", scopes)
	}
}

func mustHeld(t *testing.T, k *testkit.Kit, person string) []*basev0.WorkScopeV1 {
	t.Helper()
	held, err := k.PersonScopes(t, person, "ledger")
	if err != nil {
		t.Fatal(err)
	}
	return held
}

// Installations and stand-in modules take the fixture's own path.
func TestCompositionInstallsItsSolutionsAndStandsInForModules(t *testing.T) {
	k := fixtureOnly(t)
	lines, err := k.State.ApplyComposition(context.Background(), []byte(head+`
installations:
  - {organization: acme, target: atlas, role: viewer, owner: alex, teams: [finance]}
modules:
  - module: oracle
    kinds: [{kind: oracle.answers, actions: [read]}]
`))
	if err != nil || len(lines) != 2 {
		t.Fatalf("apply: %v %v", lines, err)
	}
	if err := k.State.AdmitMethod("oracle", "/oracle/Read", nil); err == nil || !strings.Contains(err.Error(), "no method policy") {
		t.Errorf("the stand-in oracle is not composed: %v", err)
	}
}

// A composition grants concrete permissions to roles the fixture defines, and
// a refused document changes nothing.
func TestCompositionRefusesByName(t *testing.T) {
	// A valid entry prepended to every roles case below, so a refused later
	// entry cannot leave it applied. Its kind differs from the cases' own:
	// one document states each (organisation, role, kind) once, so reusing
	// ledger.entry here would make every case a duplicate and hide what it
	// is actually testing.
	valid := `{organization: acme, name: editor, scopes: [{kind: ledger.audit, actions: [read]}]}`
	for name, tc := range map[string]struct{ doc, reason string }{
		"empty":             {"", "the document is empty"},
		"null":              {"null", "not a mapping"},
		"empty mapping":     {"{}", "schema is \"\""},
		"no schema":         {`{roles: [` + valid + `]}`, "schema is \"\""},
		"other schema":      {"schema: codefly.dev/authority/fixture-composition/v2\n", "this authority reads"},
		"null roles":        {head + "roles: null\n", "roles is null"},
		"null installs":     {head + "installations:\n", "installations is null"},
		"misspelt":          {head + "grants: []\n", "field grants not found"},
		"unknown role":      {head + `roles: [{organization: acme, name: auditor, scopes: [{kind: ledger.entry, actions: [read]}]}]`, "acme/auditor is not a role the fixture defines"},
		"other org":         {head + `roles: [{organization: initech, name: admin, scopes: [{kind: ledger.entry, actions: [read]}]}]`, "initech/admin is not a role"},
		"developer":         {head + `roles: [{organization: acme, name: developer, scopes: [{kind: ledger.entry, actions: [read]}]}]`, "derived from the delivered catalog"},
		"no scope":          {head + `roles: [{organization: acme, name: editor}]`, "acme/editor names no scope"},
		"no action":         {head + `roles: [{organization: acme, name: editor, scopes: [{kind: ledger.entry}]}]`, "names no action"},
		"wildcard kind":     {head + `roles: [{organization: acme, name: viewer, scopes: [{kind: "*", actions: [read]}]}]`, "wildcard kind"},
		"wildcard action":   {head + `roles: [{organization: acme, name: viewer, scopes: [{kind: ledger.entry, actions: ["*"]}]}]`, "wildcard action"},
		"padded kind":       {head + `roles: [{organization: acme, name: editor, scopes: [{kind: " ledger.entry", actions: [read]}]}]`, "is not a kind"},
		"padded action":     {head + `roles: [{organization: acme, name: editor, scopes: [{kind: ledger.entry, actions: [" read"]}]}]`, "is not an action"},
		"bad resource":      {head + `roles: [{organization: acme, name: editor, scopes: [{kind: ledger.entry, actions: [read], resources: [{}]}]}]`, "acme/editor scope ledger.entry"},
		"stranger owner":    {head + `installations: [{organization: acme, target: atlas, role: viewer, owner: zoe}]`, "not a person of acme"},
		"no target":         {head + `installations: [{organization: acme, role: viewer, owner: alex}]`, "no target or no role"},
		"wildcard stand-in": {head + `modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: ["*"]}]}]`, "wildcard action"},
	} {
		t.Run(name, func(t *testing.T) {
			k := fixtureOnly(t)
			before := k.State.RoleScopes("acme", "editor")
			doc := tc.doc
			// A valid first entry must not survive a refused later one.
			if strings.HasPrefix(doc, head+"roles: [") {
				doc = strings.Replace(doc, "roles: [", "roles: ["+valid+", ", 1)
			}
			_, err := k.State.ApplyComposition(context.Background(), []byte(doc))
			if err == nil || !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), state.CompositionDocument) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.reason)
			}
			after := k.State.RoleScopes("acme", "editor")
			if !state.Attenuates(before, after) || !state.Attenuates(after, before) {
				t.Fatalf("a refused document changed the editor: %v → %v", before, after)
			}
		})
	}
}

// The module's shipped default adds nothing.
func TestTheShippedDefaultAddsNothing(t *testing.T) {
	k := fixtureOnly(t)
	data, err := os.ReadFile(testkit.DefaultCompositionPath())
	if err != nil {
		t.Fatal(err)
	}
	if lines, err := k.State.ApplyComposition(context.Background(), data); err != nil || len(lines) != 0 {
		t.Fatalf("%v %v", lines, err)
	}
}

// A document the fixture validates but that fails while being APPLIED leaves
// every role as it was: the applying step that can fail runs before the one
// that cannot.
//
// The document has to fail INSIDE LoadFixture to exercise that, which is the
// whole point of the ordering. A refused installation does not: an owner the
// fixture does not define is caught by checkComposedSetup, pure validation
// that runs before either applying step in both orderings, so such a document
// never reaches the code the ordering moves. A stand-in module named after a
// fixture person does: checkComposedSetup only checks its kinds and logs a
// line, and the core refuses it when the manifest is applied ("names a
// person; a module's principal is its own"). With the role writes first, that
// left the editor holding the grant from a document that was refused.
func TestADocumentRefusedWhileApplyingLeavesTheRolesAlone(t *testing.T) {
	k := fixtureOnly(t)
	before := k.State.RoleScopes("acme", "editor")
	lines, err := k.State.ApplyComposition(context.Background(), []byte(head+`
roles:
  - organization: acme
    name: editor
    scopes:
      - {kind: ledger.entry, actions: [approve]}
modules:
  - module: maya
    kinds: [{kind: maya.things, actions: [read]}]
`))
	if err == nil || !strings.Contains(err.Error(), "names a person") {
		t.Fatalf("got %v (%v), want the stand-in module refused while applying", err, lines)
	}
	after := k.State.RoleScopes("acme", "editor")
	if !state.Attenuates(before, after) || !state.Attenuates(after, before) {
		t.Fatalf("a refused document granted the editor anyway: %v → %v", before, after)
	}
}
