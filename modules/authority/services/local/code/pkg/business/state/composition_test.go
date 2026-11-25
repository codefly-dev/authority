package state_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"

	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
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
			"/ledger/Read":    {Requires: []*basev1.WorkScopeV1{testkit.Scope("ledger.entry", "read")}},
			"/ledger/Write":   {Requires: []*basev1.WorkScopeV1{testkit.Scope("ledger.entry", "write")}},
			"/ledger/Approve": {Requires: []*basev1.WorkScopeV1{testkit.Scope("ledger.entry", "approve")}},
		}}
	if _, err := k.State.ApplyManifest(ledger); err != nil {
		t.Fatal(err)
	}
	return k
}

// nobodyHoldsTheLedger requires that no fixture person, the administrators
// included, holds anything at the ledger on their own session.
func nobodyHoldsTheLedger(t *testing.T, k *testkit.Kit, when string) {
	t.Helper()
	for _, person := range []string{"sarah", "alice", "bob", "carol", "dana", "maya", "remi", "alex", "dev", "zoe"} {
		held, err := k.PersonScopes(t, person, "ledger")
		if err == nil || len(held) != 0 || !strings.Contains(err.Error(), "ledger declares no roles") {
			t.Fatalf("%s: %s holds %v at ledger (%v), want a refusal naming that it declares no roles", when, person, held, err)
		}
	}
}

// No organisation role reaches a module: the embedded fixture grants nothing
// at one, and no composition can. A document that tries is refused by name
// and changes nothing; so is the schema that could.
func TestNoCompositionGrantsAnOrganisationRoleAModulesKinds(t *testing.T) {
	k := fixtureOnly(t)
	nobodyHoldsTheLedger(t, k, "the fixture alone")
	for name, tc := range map[string]struct{ doc, reason string }{
		"a roles section": {head + `
roles:
  - organization: acme
    name: admin
    scopes:
      - {kind: ledger.entry, actions: [read, write, approve]}
`, "a composition grants no organisation role a module's kinds"},
		"a roles section under an unknown schema": {`schema: codefly.dev/authority/fixture-composition/v2
roles:
  - organization: acme
    name: admin
    scopes:
      - {kind: ledger.entry, actions: [approve]}
`, "a composition grants no organisation role a module's kinds"},
		"an unknown schema": {`schema: codefly.dev/authority/fixture-composition/v2
installations: []
`, "state the schema as codefly.dev/authority/fixture-composition/v1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := k.State.ApplyComposition(context.Background(), []byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), state.CompositionDocument) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.reason)
			}
			nobodyHoldsTheLedger(t, k, name)
		})
	}
}

// A fixture role is a name: one that states what it grants, as the fixture
// once could, is refused by name.
func TestAFixtureRoleStatesNoGrant(t *testing.T) {
	for name, doc := range map[string]string{
		"scopes":    "organizations: [{id: acme, name: Acme}]\nroles: [{organization: acme, name: viewer, scopes: [{kind: console.identity, actions: [read]}]}]\n",
		"generated": "organizations: [{id: acme, name: Acme}]\nroles: [{organization: acme, name: developer, generated: true}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := testkit.Bare(t).State.LoadFixture(context.Background(), []byte(doc))
			if err == nil || !strings.Contains(err.Error(), "an organisation role decides administration only") {
				t.Fatalf("got %v, want the role refused for stating a grant", err)
			}
		})
	}
}

// A person reaches a module through a role on an installation: a row naming a
// role-gated target seats its members on that target's role teams, and they
// hold exactly that role there.
func TestACompositionSeatsPeopleOnAnInstallationsRoles(t *testing.T) {
	k := fixtureOnly(t)
	page := state.Manifest{Name: "ledger-page", Principal: "ledger-page", Kind: "module", Generation: 1, Page: true, InstallationRole: "none",
		ResourceKinds: []*basev1.WorkScopeV1{testkit.Scope("ledger-page.note", "read", "write")},
		Roles: map[string][]*basev1.WorkScopeV1{
			state.AdminRole: {testkit.Scope("ledger-page.note", "read", "write")},
			state.UserRole:  {testkit.Scope("ledger-page.note", "read")},
		}}
	if _, err := k.State.ApplyManifest(page); err != nil {
		t.Fatal(err)
	}
	if held, err := k.PersonScopes(t, "maya", "ledger-page"); err == nil || len(held) != 0 {
		t.Fatalf("before she is seated maya holds %v at the page (%v)", held, err)
	}
	if _, err := k.State.ApplyComposition(context.Background(), []byte(head+`
installations:
  - organization: acme
    target: ledger-page
    owner: alice
    members: {user: [maya], admin: [remi]}
`)); err != nil {
		t.Fatal(err)
	}
	for person, want := range map[string]*basev1.WorkScopeV1{
		"maya": testkit.Scope("ledger-page.note", "read"),
		"remi": testkit.Scope("ledger-page.note", "read", "write"),
	} {
		held, err := k.PersonScopes(t, person, "ledger-page")
		if err != nil || !state.Attenuates([]*basev1.WorkScopeV1{want}, held) || !state.Attenuates(held, []*basev1.WorkScopeV1{want}) {
			t.Errorf("%s holds %v at the page (%v), want exactly %v", person, held, err, want)
		}
	}
	// Alex administers acme and was seated nowhere: nothing.
	if held, err := k.PersonScopes(t, "alex", "ledger-page"); err == nil || len(held) != 0 {
		t.Fatalf("alex holds %v at the page (%v)", held, err)
	}
}

// Installations and stand-in modules take the fixture's own path.
func TestCompositionInstallsItsSolutionsAndStandsInForModules(t *testing.T) {
	k := fixtureOnly(t)
	lines, err := k.State.ApplyComposition(context.Background(), []byte(head+`
installations:
  - {organization: acme, target: atlas, role: user, owner: alex, teams: [finance]}
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

// A refused document changes nothing.
func TestCompositionRefusesByName(t *testing.T) {
	for name, tc := range map[string]struct{ doc, reason string }{
		"empty":             {"", "the document is empty"},
		"null":              {"null", "not a mapping"},
		"empty mapping":     {"{}", "schema is \"\""},
		"other schema":      {"schema: codefly.dev/authority/fixture-composition/v999-not-a-schema\n", "this authority reads"},
		"null installs":     {head + "installations:\n", "installations is null"},
		"misspelt":          {head + "grants: []\n", "field grants not found"},
		"stranger owner":    {head + `installations: [{organization: acme, target: atlas, role: user, owner: zoe}]`, "not a person of acme"},
		"no target":         {head + `installations: [{organization: acme, role: user, owner: alex}]`, "names no target"},
		"wildcard stand-in": {head + `modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: ["*"]}]}]`, "wildcard action"},
		"padded kind":       {head + `modules: [{module: oracle, kinds: [{kind: " oracle.answers", actions: [read]}]}]`, "is not a kind"},
		"no action":         {head + `modules: [{module: oracle, kinds: [{kind: oracle.answers}]}]`, "names no action"},
	} {
		t.Run(name, func(t *testing.T) {
			k := fixtureOnly(t)
			_, err := k.State.ApplyComposition(context.Background(), []byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), state.CompositionDocument) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.reason)
			}
			if _, composed := k.State.Module("oracle"); composed {
				t.Fatal("a refused document composed its stand-in module")
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
