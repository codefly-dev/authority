package roleplan_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/roleplan"
	modulecontract "github.com/codefly-dev/core/contracts/module"
)

// publishedContract is a module's contract as it publishes it
// (testdata/published): robin's, whose `run` includes the model gateway's
// `infer`, and the model gateway's.
func publishedContract(t *testing.T, module string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "published", module+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// bundles is what Published answers bundles with: core's reader of a role's
// includes takes it from the Callees a product is rendered with.
func bundles(t *testing.T, contracts ...[]byte) modulecontract.Bundles {
	t.Helper()
	published, err := roleplan.Published(contracts...)
	if err != nil {
		t.Fatal(err)
	}
	answers, ok := published.(modulecontract.Bundles)
	if !ok {
		t.Fatal("Published answers no bundle")
	}
	return answers
}

// granted spells a bundle "<kind>:<action> through <place>", sorted.
func granted(t *testing.T, contracts [][]byte, module, bundle string) []string {
	t.Helper()
	scopes, err := bundles(t, contracts...).Bundle(module, bundle)
	if err != nil {
		t.Fatalf("bundle %s/%s: %v", module, bundle, err)
	}
	var out []string
	for _, sc := range scopes {
		for _, action := range sc.Actions {
			out = append(out, sc.ResourceKind+":"+action+" through "+sc.Through)
		}
	}
	slices.Sort(out)
	return out
}

// A bundle that includes another module's is read through every contract
// handed in: robin's `run` is its own two scopes and the model gateway's
// `infer` (which includes the gateway's own `discover`), reached through
// robin, as robin's contract says.
func TestABundleIncludingAnotherModulesIsReadFromBothContracts(t *testing.T) {
	got := granted(t, [][]byte{publishedContract(t, "robin"), publishedContract(t, "model")}, "robin", "run")
	want := []string{
		"modelservice.profiles:invoke through robin",
		"modelservice.profiles:read through robin",
		"robin.intents:run through ",
		"robin.tasks:execute through ",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("robin/run grants %q, want %q", got, want)
	}
}

// One contract alone still answers the bundles it holds whole.
func TestABundleOfOneContractIsReadFromItAlone(t *testing.T) {
	got := granted(t, [][]byte{publishedContract(t, "model")}, "model", "infer")
	want := []string{"modelservice.profiles:invoke through ", "modelservice.profiles:read through "}
	if !slices.Equal(got, want) {
		t.Fatalf("model/infer grants %q, want %q", got, want)
	}
}

// A bundle whose include reaches a module no contract was handed in for is
// refused naming that module and the ones that were read.
func TestABundleIncludingAnUnreadModuleNamesIt(t *testing.T) {
	published := bundles(t, publishedContract(t, "robin"), publishedContract(t, "model"))
	_, err := published.Bundle("robin", "chat")
	if err == nil {
		t.Fatal("robin/chat includes the document store's read, whose contract was not handed in; it must be refused")
	}
	for _, want := range []string{"no contract was supplied for module", "supplied: model, robin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
	if _, err := published.Bundle("documents", "read"); err == nil || !strings.Contains(err.Error(), "documents") {
		t.Errorf("a module no contract was handed in for must be refused by name, got %v", err)
	}
}

// A product whose role includes robin's `run` composes: what the role holds is
// robin's bundle with the model gateway's followed, so its holder reaches the
// gateway's profiles through the product's binding to robin, and a plan is
// held to it.
func TestARoleIncludingABundleThatIncludesAnotherModulesHolds(t *testing.T) {
	c := `schema: codefly/module-contract/v1
principal: notebook
owner_aware: true
installation_role: none
namespaces: []
queues: []
scope_ceilings:
    - resource_kind: notebook.note
      actions: [read]
roles:
    - name: admin
      includes:
          - {module: robin, bundle: run}
      scopes:
          - resource_kind: notebook.note
            actions: [read]
    - name: user
      scopes:
          - resource_kind: notebook.note
            actions: [read]
bindings:
    - id: robin
      operations: [invoke]
      audience: {from: notebook-audiences/robin-audience}
      scope_ceiling:
          invoke:
              - resource_kind: robin.intents
                actions: [run]
              - resource_kind: robin.tasks
                actions: [execute]
`
	p := product(t, c)
	if err := os.WriteFile(filepath.Join(p.Configurations, "notebook-audiences.env"), []byte("robin-audience=robin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.Methods = map[string]roleplan.Policy{"GET /v1/notebook/notes": {Requires: []string{"notebook.note:read"}}}
	callees, err := roleplan.Published(publishedContract(t, "robin"), publishedContract(t, "model"))
	if err != nil {
		t.Fatal(err)
	}
	p.Callees = callees

	m, err := roleplan.Module(p)
	if err != nil {
		t.Fatalf("the product does not compose: %v", err)
	}
	var through []string
	for _, sc := range m.Through[domain.AdminRole]["robin"] {
		for _, action := range sc.GetActions() {
			through = append(through, sc.GetResourceKind()+":"+action)
		}
	}
	slices.Sort(through)
	if want := []string{"modelservice.profiles:invoke", "modelservice.profiles:read"}; !slices.Equal(through, want) {
		t.Fatalf("the admin role names %q through its binding to robin, want %q", through, want)
	}

	A, N, B := roleplan.Allowed, roleplan.RefusedNoRole, roleplan.RefusedAtBinding
	roleplan.Assert(t, roleplan.Plan{Product: p, Rows: []roleplan.Row{
		{Name: "read notes", Method: "GET /v1/notebook/notes", Admin: A, User: A, None: N},
		{Name: "the page runs an intent", Binding: "robin", Asks: []string{"robin.intents:run", "robin.tasks:execute"},
			Onward: []string{"modelservice.profiles:invoke", "modelservice.profiles:read"}, Admin: A, User: B, None: N},
	}})
}
