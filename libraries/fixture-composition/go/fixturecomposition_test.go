package fixturecomposition_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	fixturecomposition "github.com/codefly-dev/authority/libraries/fixture-composition/go"
)

const head = "schema: codefly.dev/authority/fixture-composition/v1\n"

// Two modules' fragments and the composition's own merge into one document
// that holds each source's grants, in an order that does not depend on the
// order the sources were given in, and that reads back unchanged.
func TestMergeTwoModuleFragmentsAndTheCompositionsOwn(t *testing.T) {
	store := fixturecomposition.Source{Name: "module documents", Data: []byte(head + `
roles:
  - organization: acme
    name: viewer
    scopes:
      - {kind: documents, actions: [read]}
  - organization: acme
    name: admin
    scopes:
      - {kind: documents, actions: [read, write, ingest]}
      - {kind: documents.collection, actions: [read, transfer, admin, publish, freeze]}
`)}
	chat := fixturecomposition.Source{Name: "module robin", Data: []byte(head + `
roles:
  - organization: acme
    name: viewer
    scopes:
      - {kind: robin.conversations, actions: [read]}
`)}
	own := fixturecomposition.Source{Name: "module robin-playground", Data: []byte(head + `
roles:
  - organization: acme
    name: viewer
    scopes:
      - kind: documents.collection
        actions: [read]
        resources: [{id: "derived\x1frobin-playground"}]
installations:
  - {organization: acme, target: atlas, role: viewer, owner: alex, teams: [finance]}
`)}
	empty := fixturecomposition.Source{Name: "module authority", Data: []byte(head)}

	merged, err := fixturecomposition.Merge([]fixturecomposition.Source{own, chat, store, empty})
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := fixturecomposition.Merge([]fixturecomposition.Source{empty, store, chat, own})
	if err != nil || !reflect.DeepEqual(merged, reordered) {
		t.Fatalf("the merge depends on the order of its sources: %v", err)
	}
	var viewer []string
	for _, r := range merged.Roles {
		if r.Key() == "acme/viewer" {
			for _, sc := range r.Scopes {
				viewer = append(viewer, sc.Kind)
			}
		}
	}
	if want := []string{"documents", "robin.conversations", "documents.collection"}; !reflect.DeepEqual(viewer, want) {
		t.Fatalf("the viewer holds %v, want %v", viewer, want)
	}
	if len(merged.Installations) != 1 || merged.Installations[0].Target != "atlas" {
		t.Fatalf("installations: %+v", merged.Installations)
	}

	encoded, err := fixturecomposition.Encode(merged)
	if err != nil {
		t.Fatal(err)
	}
	back, err := fixturecomposition.Decode(encoded)
	if err != nil || !reflect.DeepEqual(back, merged) {
		t.Fatalf("the encoded merge does not read back: %v\n%s", err, encoded)
	}
	if !strings.Contains(strings.ToLower(string(encoded)), `"derived\x1frobin-playground"`) {
		t.Fatalf("the seeded id lost its separator:\n%s", encoded)
	}
}

// A grant one source owns that another restates is refused naming both, even
// when the two agree; so are an installation and a stand-in module stated
// twice, and two sources of one name.
func TestMergeRefusesAConflictNamingBothSources(t *testing.T) {
	module := fixturecomposition.Source{Name: "module documents", Data: []byte(head + `
roles: [{organization: acme, name: viewer, scopes: [{kind: documents.collection, actions: [read]}]}]
installations: [{organization: acme, target: atlas, role: viewer, owner: alex}]
modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: [read]}]}]
`)}
	for name, tc := range map[string]struct {
		other  string
		reason string
	}{
		"narrowed grant": {`roles: [{organization: acme, name: viewer, scopes: [{kind: documents.collection, actions: [read], resources: [{id: seeded}]}]}]`,
			"acme/viewer's grant on documents.collection is stated by module documents and by module playground"},
		"agreeing grant": {`roles: [{organization: acme, name: viewer, scopes: [{kind: documents.collection, actions: [read]}]}]`,
			"acme/viewer's grant on documents.collection"},
		"installation": {`installations: [{organization: acme, target: atlas, role: editor, owner: alex}]`,
			"the installation of atlas at acme is stated by module documents and by module playground"},
		"stand-in": {`modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: [write]}]}]`,
			"stand-in module oracle is stated by module documents and by module playground"},
	} {
		t.Run(name, func(t *testing.T) {
			other := fixturecomposition.Source{Name: "module playground", Data: []byte(head + tc.other + "\n")}
			_, err := fixturecomposition.Merge([]fixturecomposition.Source{other, module})
			if !errors.Is(err, fixturecomposition.ErrConflict) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want a conflict naming %q", err, tc.reason)
			}
		})
	}
	// Another role, another organisation or another kind is not a conflict.
	for _, other := range []string{
		`roles: [{organization: acme, name: editor, scopes: [{kind: documents.collection, actions: [read]}]}]`,
		`roles: [{organization: globex, name: viewer, scopes: [{kind: documents.collection, actions: [read]}]}]`,
		`roles: [{organization: acme, name: viewer, scopes: [{kind: documents, actions: [read]}]}]`,
	} {
		if _, err := fixturecomposition.Merge([]fixturecomposition.Source{module, {Name: "module playground", Data: []byte(head + other + "\n")}}); err != nil {
			t.Errorf("%s: %v", other, err)
		}
	}
	if _, err := fixturecomposition.Merge([]fixturecomposition.Source{module, module}); err == nil || !strings.Contains(err.Error(), "both named module documents") {
		t.Fatalf("two sources of one name: %v", err)
	}
}

// A fragment that does not read is refused naming its source, and the
// document's own rules hold in a fragment as they do in the merged result.
func TestMergeNamesTheFragmentThatDoesNotRead(t *testing.T) {
	for name, tc := range map[string]struct{ doc, reason string }{
		"empty":           {"", "the document is empty"},
		"null":            {"null", "not a mapping"},
		"other schema":    {"schema: codefly.dev/authority/fixture-composition/v2\n", "this authority reads"},
		"null roles":      {head + "roles: null\n", "roles is null"},
		"misspelt":        {head + "grants: []\n", "field grants not found"},
		"generated":       {head + `roles: [{organization: acme, name: developer, generated: true, scopes: [{kind: ledger.entry, actions: [read]}]}]`, "field generated not found"},
		"no scope":        {head + `roles: [{organization: acme, name: editor}]`, "acme/editor names no scope"},
		"wildcard kind":   {head + `roles: [{organization: acme, name: viewer, scopes: [{kind: "*", actions: [read]}]}]`, "wildcard kind"},
		"wildcard action": {head + `roles: [{organization: acme, name: viewer, scopes: [{kind: ledger.entry, actions: ["*"]}]}]`, "wildcard action"},
		"padded action":   {head + `roles: [{organization: acme, name: editor, scopes: [{kind: ledger.entry, actions: [" read"]}]}]`, "is not an action"},
		"bad resource":    {head + `roles: [{organization: acme, name: editor, scopes: [{kind: ledger.entry, actions: [read], resources: [{}]}]}]`, "acme/editor scope ledger.entry"},
		"no target":       {head + `installations: [{organization: acme, role: viewer, owner: alex}]`, "no target or no role"},
		"bad stand-in":    {head + `modules: [{module: Oracle, kinds: [{kind: oracle.answers, actions: [read]}]}]`, "names no valid module"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixturecomposition.Merge([]fixturecomposition.Source{{Name: "module ledger", Data: []byte(tc.doc)}})
			if err == nil || !strings.Contains(err.Error(), tc.reason) || !strings.HasPrefix(err.Error(), "module ledger: ") {
				t.Fatalf("got %v, want a refusal of module ledger naming %q", err, tc.reason)
			}
		})
	}
}

// No fragment merges to the schema line alone, which the local authority
// reads as a composition that adds nothing.
func TestMergeOfNothingIsTheSchemaAlone(t *testing.T) {
	merged, err := fixturecomposition.Merge(nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := fixturecomposition.Encode(merged)
	if err != nil || string(encoded) != head {
		t.Fatalf("%q %v", encoded, err)
	}
}
