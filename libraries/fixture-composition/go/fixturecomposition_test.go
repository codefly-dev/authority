package fixturecomposition_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	fixturecomposition "github.com/codefly-dev/authority/libraries/fixture-composition/go"
)

const head = "schema: codefly.dev/authority/fixture-composition/v1\n"

// The document grants no organisation role anything: organisation roles decide
// administration only, and a person reaches a module through a role on an
// installation. A document that still carries a roles section is refused by
// name, with what to write instead, whatever schema it states and wherever
// the section is written. A
// refusal, never a section read as "grants nothing": a fixture person who
// reached a module through such a grant no longer does, and the document says
// why.
func TestTheDocumentGrantsNoOrganisationRoleAModulesKinds(t *testing.T) {
	const grant = "roles: [{organization: acme, name: admin, scopes: [{kind: evaluation.labels, actions: [approve]}]}]\n"
	for name, tc := range map[string]struct{ doc, reason string }{
		"a roles section":         {head + grant, "roles: a composition grants no organisation role a module's kinds"},
		"an empty roles section":  {head + "roles: []\n", "roles: a composition grants no organisation role a module's kinds"},
		"a null roles section":    {head + "roles: null\n", "roles: a composition grants no organisation role a module's kinds"},
		"the section first":       {grant + head, "roles: a composition grants no organisation role a module's kinds"},
		"under an unknown schema": {"schema: codefly.dev/authority/fixture-composition/v2\n" + grant, "roles: a composition grants no organisation role a module's kinds"},
		"under no schema":         {grant, "roles: a composition grants no organisation role a module's kinds"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixturecomposition.Decode([]byte(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.reason)
			}
			// The refusal says where a person's reach is stated now.
			if !strings.Contains(err.Error(), "a role on an installation") {
				t.Fatalf("the refusal does not say how a person reaches a module: %v", err)
			}
			_, err = fixturecomposition.Merge([]fixturecomposition.Source{{Name: "module evaluation", Data: []byte(tc.doc)}})
			if err == nil || !strings.HasPrefix(err.Error(), "module evaluation: ") || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("the merge does not name the fragment: %v", err)
			}
		})
	}
	// What a person reaches is stated by seating them: a member of a role's
	// team on an installation.
	doc, err := fixturecomposition.Decode([]byte(head + `installations:
  - organization: acme
    target: evaluation-playground
    owner: alice
    members: {admin: [alex], user: [maya]}
`))
	if err != nil || len(doc.Installations) != 1 || !reflect.DeepEqual(doc.Installations[0].Members, map[string][]string{"admin": {"alex"}, "user": {"maya"}}) {
		t.Fatalf("%+v %v", doc.Installations, err)
	}
}

// Two modules' fragments and the composition's own merge into one document
// that holds each source's statements, in an order that does not depend on
// the order the sources were given in, and that reads back unchanged.
func TestMergeTwoModuleFragmentsAndTheCompositionsOwn(t *testing.T) {
	store := fixturecomposition.Source{Name: "module documents", Data: []byte(head + `
modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: [read]}]}]
`)}
	chat := fixturecomposition.Source{Name: "module robin", Data: []byte(head + `
installations:
  - {organization: acme, target: robin-playground, owner: alice, members: {user: [maya]}}
`)}
	own := fixturecomposition.Source{Name: "module robin-playground", Data: []byte(head + `
installations:
  - {organization: acme, target: atlas, role: user, owner: alex, teams: [finance]}
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
	var targets []string
	for _, i := range merged.Installations {
		targets = append(targets, i.Target)
	}
	if want := []string{"robin-playground", "atlas"}; !reflect.DeepEqual(targets, want) {
		t.Fatalf("installations %v, want %v", targets, want)
	}
	if len(merged.Modules) != 1 || merged.Modules[0].Module != "oracle" {
		t.Fatalf("modules: %+v", merged.Modules)
	}

	encoded, err := fixturecomposition.Encode(merged)
	if err != nil {
		t.Fatal(err)
	}
	back, err := fixturecomposition.Decode(encoded)
	if err != nil || !reflect.DeepEqual(back, merged) {
		t.Fatalf("the encoded merge does not read back: %v\n%s", err, encoded)
	}
}

// A statement one source owns that another restates is refused naming both,
// even when the two agree: an installation and a stand-in module stated
// twice, and two sources of one name.
func TestMergeRefusesAConflictNamingBothSources(t *testing.T) {
	module := fixturecomposition.Source{Name: "module documents", Data: []byte(head + `
installations: [{organization: acme, target: atlas, role: user, owner: alex}]
modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: [read]}]}]
`)}
	for name, tc := range map[string]struct {
		other  string
		reason string
	}{
		"installation": {`installations: [{organization: acme, target: atlas, role: admin, owner: alex}]`,
			"the installation of atlas at acme is stated by module documents and by module playground"},
		"agreeing installation": {`installations: [{organization: acme, target: atlas, role: user, owner: alex}]`,
			"the installation of atlas at acme"},
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
	// Another organisation or another target is not a conflict.
	for _, other := range []string{
		`installations: [{organization: globex, target: atlas, role: user, owner: zoe}]`,
		`installations: [{organization: acme, target: wiki, role: user, owner: alex}]`,
		`modules: [{module: sibyl, kinds: [{kind: oracle.answers, actions: [read]}]}]`,
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
		"empty":             {"", "the document is empty"},
		"null":              {"null", "not a mapping"},
		"other schema":      {"schema: codefly.dev/authority/fixture-composition/v999-not-a-schema\n", "this authority reads"},
		"null section":      {head + "installations: null\n", "installations is null"},
		"misspelt":          {head + "grants: []\n", "field grants not found"},
		"no target":         {head + `installations: [{organization: acme, role: user, owner: alex}]`, "names no target"},
		"teams no role":     {head + `installations: [{organization: acme, target: atlas, owner: alex, teams: [finance]}]`, "grants teams and names no role"},
		"bad stand-in":      {head + `modules: [{module: Oracle, kinds: [{kind: oracle.answers, actions: [read]}]}]`, "names no valid module"},
		"wildcard kind":     {head + `modules: [{module: oracle, kinds: [{kind: "*", actions: [read]}]}]`, "wildcard kind"},
		"wildcard action":   {head + `modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: ["*"]}]}]`, "wildcard action"},
		"padded action":     {head + `modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: [" read"]}]}]`, "is not an action"},
		"a kind's resource": {head + `modules: [{module: oracle, kinds: [{kind: oracle.answers, actions: [read], resources: [{id: x}]}]}]`, "field resources not found"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixturecomposition.Merge([]fixturecomposition.Source{{Name: "module ledger", Data: []byte(tc.doc)}})
			if err == nil || !strings.Contains(err.Error(), tc.reason) || !strings.HasPrefix(err.Error(), "module ledger: ") {
				t.Fatalf("got %v, want a refusal of module ledger naming %q", err, tc.reason)
			}
		})
	}
}

// A row installing a target that declares its own agent role
// (installation_role, `none` included) names no role: the authority refuses a
// role overriding the declaration. It grants no team either, since a row's
// teams take its role.
func TestARowWithNoRoleInstallsWithTheTargetsDeclaration(t *testing.T) {
	doc := head + "installations: [{organization: acme, target: wiki, owner: alex}]\n"
	merged, err := fixturecomposition.Merge([]fixturecomposition.Source{{Name: "module wiki", Data: []byte(doc)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Installations) != 1 || merged.Installations[0].Role != "" || merged.Installations[0].Target != "wiki" {
		t.Fatalf("installations: %+v", merged.Installations)
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

// The one-statement-one-source rule holds inside a fragment too: whoever reads
// the first statement of an installation or a stand-in module has no reason to
// look for a second further down the file.
func TestADocumentStatingOneThingTwiceIsRefused(t *testing.T) {
	for name, tc := range map[string]struct{ doc, reason string }{
		"installation": {`installations:
  - {organization: acme, target: atlas, role: user, owner: alex}
  - {organization: acme, target: atlas, role: admin, owner: alex}`,
			"the installation of atlas at acme is stated twice"},
		"stand-in": {`modules:
  - {module: oracle, kinds: [{kind: oracle.answers, actions: [read]}]}
  - {module: oracle, kinds: [{kind: oracle.answers, actions: [write]}]}`,
			"stand-in module oracle is stated twice"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixturecomposition.Decode([]byte(head + tc.doc + "\n"))
			if !errors.Is(err, fixturecomposition.ErrConflict) || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want a conflict naming %q", err, tc.reason)
			}
			// The merge names the fragment it came from.
			_, err = fixturecomposition.Merge([]fixturecomposition.Source{{Name: "module ledger", Data: []byte(head + tc.doc + "\n")}})
			if !errors.Is(err, fixturecomposition.ErrConflict) || !strings.HasPrefix(err.Error(), "module ledger: ") {
				t.Fatalf("got %v, want the conflict named against module ledger", err)
			}
		})
	}
	// One target at two organisations is not a duplicate.
	doc := `installations: [{organization: acme, target: atlas, role: user, owner: alex}, {organization: globex, target: atlas, role: user, owner: zoe}]`
	if _, err := fixturecomposition.Decode([]byte(head + doc + "\n")); err != nil {
		t.Errorf("%s: %v", doc, err)
	}
}

// A row standing for every role-gated target names its owner and the members
// of each role, and nothing one target's: no role, no teams. Its members
// read back as written.
func TestARowStandingForEveryTargetNamesOnlyOwnerAndMembers(t *testing.T) {
	doc, err := fixturecomposition.Decode([]byte(head + `installations:
  - organization: acme
    target: "*"
    owner: alice
    members: {user: [carol], admin: [dana]}
`))
	if err != nil || len(doc.Installations) != 1 || doc.Installations[0].Target != fixturecomposition.EveryTarget || len(doc.Installations[0].Members["admin"]) != 1 {
		t.Fatalf("%+v %v", doc.Installations, err)
	}
	for name, tc := range map[string]struct{ doc, reason string }{
		"a role":        {`installations: [{organization: acme, target: "*", role: user, owner: alice}]`, "names only its owner and members"},
		"teams":         {`installations: [{organization: acme, target: "*", owner: alice, teams: [finance]}]`, "names only its owner and members"},
		"empty members": {`installations: [{organization: acme, target: "*", owner: alice, members: {user: []}}]`, "members name a role and the people"},
		"blank role":    {`installations: [{organization: acme, target: wiki, role: user, owner: alice, members: {"": [bob]}}]`, "members name a role and the people"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixturecomposition.Decode([]byte(head + tc.doc + "\n")); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("got %v, want a refusal naming %q", err, tc.reason)
			}
		})
	}
}

// There is one schema, v1, and it is the current format. A v1 document as it
// was once written, with a roles section, is refused for the section; one
// with the current sections and none is read; and a document stating any
// other schema (the v2 this format was briefly called) is refused as unknown,
// telling its author to state v1.
func TestThereIsOneSchema(t *testing.T) {
	if fixturecomposition.Schema != "codefly.dev/authority/fixture-composition/v1" {
		t.Fatalf("the schema is %s", fixturecomposition.Schema)
	}
	const current = `installations:
  - organization: acme
    target: wiki
    owner: alex
    members: {user: [maya]}
modules:
  - module: oracle
    kinds: [{kind: oracle.answers, actions: [read]}]
`
	const v1 = "schema: codefly.dev/authority/fixture-composition/v1\n"
	_, err := fixturecomposition.Decode([]byte(v1 + "roles: [{organization: acme, name: admin, scopes: [{kind: ledger.entry, actions: [write]}]}]\n" + current))
	if err == nil || !strings.Contains(err.Error(), "roles: a composition grants no organisation role a module's kinds") || !strings.Contains(err.Error(), "remove the roles section") {
		t.Fatalf("a v1 document with a roles section: %v", err)
	}
	doc, err := fixturecomposition.Decode([]byte(v1 + current))
	if err != nil {
		t.Fatalf("a v1 document with the current sections: %v", err)
	}
	if len(doc.Installations) != 1 || len(doc.Modules) != 1 || doc.Schema != fixturecomposition.Schema {
		t.Fatalf("read %+v", doc)
	}
	for _, other := range []string{"codefly.dev/authority/fixture-composition/v2", "codefly.dev/authority/fixture-composition/v999-not-a-schema", ""} {
		_, err := fixturecomposition.Decode([]byte("schema: \"" + other + "\"\n" + current))
		if err == nil || !strings.Contains(err.Error(), "which is unknown") || !strings.Contains(err.Error(), "state the schema as codefly.dev/authority/fixture-composition/v1") {
			t.Fatalf("schema %q: %v", other, err)
		}
	}
}
