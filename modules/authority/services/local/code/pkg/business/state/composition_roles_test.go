package state_test

import (
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A composition grants the fixture's roles what its module serves; the
// fixture never names that module.
func TestCompositionGrantsFixtureRolesWhatItsModuleServes(t *testing.T) {
	k := testkit.New(t)
	ledger := state.Manifest{Module: "ledger", Principal: "ledger", Kind: "module", Generation: 1,
		Methods: map[string]state.MethodPolicy{
			"/ledger/Read":    {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "read")}},
			"/ledger/Write":   {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}},
			"/ledger/Approve": {Requires: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "approve")}},
		}}
	if _, err := k.State.ApplyManifest(ledger); err != nil {
		t.Fatal(err)
	}
	if held, _ := k.State.PersonScopes("remi", "ledger"); len(held) != 0 {
		t.Fatalf("the fixture alone grants the editor %v at ledger", held)
	}
	lines, err := k.State.GrantCompositionRoles([]byte(`
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
		t.Fatalf("grant: %v %v", lines, err)
	}
	want := map[string]*basev0.WorkScopeV1{
		"remi": testkit.Scope("ledger.entry", "read", "write"),
		"alex": testkit.Scope("ledger.entry", "approve"),
	}
	for person, scope := range want {
		held, err := k.State.PersonScopes(person, "ledger")
		if err != nil || !state.Attenuates([]*basev0.WorkScopeV1{scope}, held) {
			t.Errorf("%s holds %v at ledger (%v), want %v", person, held, err, scope)
		}
	}
	if held, _ := k.State.PersonScopes("alex", "ledger"); state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}, held) {
		t.Error("a grant to the editor reached the admin")
	}
	for _, tc := range []struct{ person, method, reason string }{
		{"remi", "/ledger/Write", ""},
		{"alex", "/ledger/Approve", ""},
		{"maya", "/ledger/Write", "ledger.entry:write"},
		{"maya", "/ledger/Approve", "ledger.entry:approve"},
		{"remi", "/ledger/Approve", "ledger.entry:approve"},
	} {
		held, err := k.State.PersonScopes(tc.person, "ledger")
		if err != nil {
			t.Fatal(err)
		}
		err = k.State.AdmitMethod("ledger", tc.method, held)
		if tc.reason == "" && err != nil {
			t.Errorf("%s %s: %v", tc.person, tc.method, err)
		}
		if tc.reason != "" && (err == nil || !strings.Contains(err.Error(), tc.reason)) {
			t.Errorf("%s %s: got %v, want refusal naming %s", tc.person, tc.method, err, tc.reason)
		}
	}
	grants, err := k.State.ResourceGrants("maya", "ledger", "ledger.entry", "read")
	if err != nil || len(grants) != 1 || grants[0].Prefix != "public-" {
		t.Errorf("the viewer's grant keeps its resources: %v %v", grants, err)
	}
	// The fixture's own grants stay: the editor still writes documents.
	if held, _ := k.State.PersonScopes("remi", "documents"); !state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("documents", "write")}, held) {
		t.Errorf("the fixture's grant was lost: %v", held)
	}
}

// A composition grants; it never creates a role, touches the generated
// developer role, or half-applies a document it refuses.
func TestCompositionRolesRefuseByName(t *testing.T) {
	for name, tc := range map[string]struct{ doc, reason string }{
		"unknown role":   {`{roles: [{organization: acme, name: auditor, scopes: [{kind: documents, actions: [read]}]}]}`, "acme/auditor is not a role the fixture defines"},
		"other org":      {`{roles: [{organization: initech, name: admin, scopes: [{kind: documents, actions: [read]}]}]}`, "initech/admin is not a role the fixture defines"},
		"developer":      {`{roles: [{organization: acme, name: developer, scopes: [{kind: documents, actions: [read]}]}]}`, "derived from the delivered catalog"},
		"no scope":       {`{roles: [{organization: acme, name: editor}]}`, "acme/editor names no scope"},
		"no action":      {`{roles: [{organization: acme, name: editor, scopes: [{kind: documents}]}]}`, "no kind or no action"},
		"empty action":   {`{roles: [{organization: acme, name: editor, scopes: [{kind: documents, actions: [" "]}]}]}`, "empty action"},
		"extra document": {"{roles: []}\n---\n{roles: []}", "expected exactly one roles document"},
		"misspelt":       {`{roles: [{organization: acme, name: editor, grants: [{kind: documents, actions: [read]}]}]}`, "field grants not found"},
		"bad resource":   {`{roles: [{organization: acme, name: editor, scopes: [{kind: documents, actions: [read], resources: [{}]}]}]}`, "acme/editor scope documents"},
	} {
		t.Run(name, func(t *testing.T) {
			k := testkit.New(t)
			before := k.State.RoleScopes("acme", "editor")
			// A valid first entry must not survive a refused second one.
			doc := strings.Replace(tc.doc, "{roles: [", "{roles: [{organization: acme, name: editor, scopes: [{kind: documents, actions: [ingest]}]}, ", 1)
			_, err := k.State.GrantCompositionRoles([]byte(doc))
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.reason)
			}
			after := k.State.RoleScopes("acme", "editor")
			if !state.Attenuates(before, after) || !state.Attenuates(after, before) {
				t.Fatalf("a refused document changed the editor: %v → %v", before, after)
			}
		})
	}
}

// An explicit empty role list grants nothing; empty or null documents are errors.
func TestEmptyCompositionRolesGrantNothing(t *testing.T) {
	k := testkit.New(t)
	if lines, err := k.State.GrantCompositionRoles([]byte("roles: []")); err != nil || len(lines) != 0 {
		t.Fatalf("%v %v", lines, err)
	}
	for _, data := range []string{"", "null"} {
		if _, err := k.State.GrantCompositionRoles([]byte(data)); err == nil || !strings.Contains(err.Error(), "empty or null") {
			t.Fatalf("%q: expected empty or null refusal, got %v", data, err)
		}
	}
}
