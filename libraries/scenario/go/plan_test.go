package scenario

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/roleplan"
	"github.com/codefly-dev/authority/libraries/hop/go/policy"
)

// A notebook with one binding to a store: its admin reads and writes the
// store, its user reads it.
const notebook = `schema: codefly/module-contract/v1
principal: notebook
owner_aware: true
installation_role: none
namespaces: []
queues: []
scope_ceilings:
    - resource_kind: notebook.note
      actions: [read, write]
roles:
    - name: admin
      scopes:
          - resource_kind: notebook.note
            actions: [read, write]
          - resource_kind: store.item
            actions: [read, write]
    - name: user
      scopes:
          - resource_kind: notebook.note
            actions: [read]
          - resource_kind: store.item
            actions: [read]
bindings:
    - id: store
      operations: [invoke]
      audience: {from: notebook-audiences/store-audience}
      scope_ceiling:
          invoke:
              - resource_kind: store.item
                actions: [read, write]
`

var cast = Seats{Admin: "dana", User: "carol", None: "bob"}

// planned is the notebook's plan with rows, and what the store publishes: a
// read, a write, a method open to any checked caller, and one no row covers.
func planned(t *testing.T, rows ...roleplan.Row) (roleplan.Plan, Published) {
	t.Helper()
	dir := t.TempDir()
	configs := filepath.Join(dir, "configurations", "local")
	if err := os.MkdirAll(configs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.contract.codefly.yaml"), []byte(notebook), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configs, "notebook-audiences.env"), []byte("store-audience=store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	requires := func(action string) policy.Method {
		return policy.Method{Requires: []policy.Permission{{Kind: "store.item", Action: action}}}
	}
	return roleplan.Plan{
		Product: roleplan.Product{Dir: dir, Name: "notebook", Configurations: configs, Kind: domain.KindSolution,
			Methods: map[string]roleplan.Policy{
				"GET /v1/notebook/notes":  {Requires: []string{"notebook.note:read"}},
				"POST /v1/notebook/notes": {Requires: []string{"notebook.note:write"}},
			}},
		Rows: rows,
	}, Published{"store": {
		"/store.v1.Store/Read":  requires("read"),
		"/store.v1.Store/Write": requires("write"),
		"/store.v1.Store/Purge": requires("purge"),
		"/store.v1.Store/Ping":  {AnyCheckedCaller: true},
	}}
}

func notebookRows() []roleplan.Row {
	A, N, P, B := roleplan.Allowed, roleplan.RefusedNoRole, roleplan.RefusedByPolicy, roleplan.RefusedAtBinding
	return []roleplan.Row{
		{Name: "read notes", Method: "GET /v1/notebook/notes", Admin: A, User: A, None: N},
		{Name: "write a note", Method: "POST /v1/notebook/notes", Admin: A, User: P, None: N},
		{Name: "the page reads the store", Binding: "store", Asks: []string{"store.item:read"}, Admin: A, User: A, None: N},
		{Name: "the page writes the store", Binding: "store", Asks: []string{"store.item:write"}, Admin: A, User: B, None: N},
	}
}

// derived is the row PlanRows derives under name.
func derived(t *testing.T, plan roleplan.Plan, published Published, name string) Row {
	t.Helper()
	rows, err := PlanRows(plan, cast, published)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	var names []string
	for _, row := range rows {
		names = append(names, row.Name)
	}
	t.Fatalf("the plan derives no row %q: %q", name, names)
	return Row{}
}

func refused(reason string) Outcome {
	return Outcome{Verdict: Denied, Status: http.StatusForbidden, Reason: reason}
}

const (
	notInstalled = `the authority refused this person at store: audience "store" is not installed in this organization, so there is no installation to seal the capability to`
	unreachable  = "the authority refused this person at store: connection refused"
)

// A refusal the plan states is held to the decision the plan names: another
// refusal (the audience not installed, the authority unreachable, a person
// simply not seated where the plan seats them, a call nobody is served) does
// not satisfy it.
func TestAPlanRefusalIsHeldToItsStage(t *testing.T) {
	plan, published := planned(t, notebookRows()...)
	for _, tc := range []struct {
		row, person string
		got         Outcome
		holds       bool
	}{
		// The user's role carries the store's read through the binding, not its write.
		{"store store.v1.Store/Write", "carol", refused("the authority refused the call to store: store requires store.item:write for /store.v1.Store/Write, which the call does not hold (it holds store.item:read)"), true},
		{"store store.v1.Store/Write", "carol", refused(notInstalled), false},
		{"store store.v1.Store/Write", "carol", refused(unreachable), false},
		{"store store.v1.Store/Write", "carol", refused("the authority refused this person at store: carol holds no role on notebook"), false},
		{"store store.v1.Store/Write", "carol", refused(`the authority refused this person at store: carol holds nothing at store through binding "store"`), false},
		// Refused for a permission it holds by the plan: another method's refusal.
		{"store store.v1.Store/Write", "carol", refused("store requires store.item:purge for /store.v1.Store/Write, which the call does not hold (it holds store.item:write)"), false},
		{"store store.v1.Store/Write", "carol", Outcome{Verdict: Unserved, Status: http.StatusNotFound, Reason: "no module serves /store.v1.Store/Write"}, false},
		{"store store.v1.Store/Write", "dana", Outcome{Verdict: Admitted, Status: http.StatusBadRequest, Code: "invalid_argument", Reason: "an item is required"}, true},
		{"store store.v1.Store/Write", "dana", Outcome{Verdict: Failed, Status: http.StatusBadGateway, Reason: "the module did not answer"}, false},
		// The member with no role is refused at the page, for holding none.
		{"store store.v1.Store/Read", "bob", refused("the authority refused this person at store: bob holds no role on notebook"), true},
		{"store store.v1.Store/Read", "bob", refused(notInstalled), false},
		{"store store.v1.Store/Read", "bob", refused("store requires store.item:read for /store.v1.Store/Read, which the call does not hold (it holds nothing)"), false},
		{"store store.v1.Store/Read", "bob", Outcome{Verdict: Unserved, Status: http.StatusNotFound, Reason: "no module serves /store.v1.Store/Read"}, false},
		// A route the notebook serves: the policy's refusal names what it requires.
		{"write a note", "carol", refused("the authority refused the call to notebook: notebook requires notebook.note:write for POST /v1/notebook/notes, which the call does not hold (it holds notebook.note:read)"), true},
		{"write a note", "carol", refused("the authority refused this person at notebook: carol holds no role on notebook"), false},
		{"write a note", "carol", refused(`the authority refused this person at notebook: audience "notebook" is not installed in this organization`), false},
		{"write a note", "bob", refused("the authority refused this person at notebook: bob holds no role on notebook"), true},
		{"write a note", "bob", refused("notebook requires notebook.note:write for POST /v1/notebook/notes, which the call does not hold (it holds nothing)"), false},
	} {
		problem := derived(t, plan, published, tc.row).Want[tc.person].problem(tc.got)
		if (problem == "") != tc.holds {
			t.Errorf("%s as %s, answered %q: problem %q, want it to hold: %v", tc.row, tc.person, tc.got.Reason, problem, tc.holds)
		}
	}
}

// A method open to any checked caller requires nothing more than a Work
// Context at its module. From a page that is the person's roles on the page:
// whoever the role reaches the module for is let through, and the member with
// no role is issued nothing and refused, for holding no role.
func TestAMethodOpenToAnyCheckedCallerIsCalledAsEachSeat(t *testing.T) {
	plan, published := planned(t, notebookRows()...)
	ping := derived(t, plan, published, "store store.v1.Store/Ping")
	if ping.Page != "notebook" || ping.Procedure != "store.v1.Store/Ping" {
		t.Fatalf("the call: %+v", ping.Call)
	}
	let := Outcome{Verdict: Allowed, Status: http.StatusOK}
	for _, tc := range []struct {
		person string
		got    Outcome
		holds  bool
	}{
		{"dana", let, true},
		{"carol", let, true},
		{"carol", refused("the authority refused this person at store: carol holds no role on notebook"), false},
		{"bob", refused("the authority refused this person at store: bob holds no role on notebook"), true},
		{"bob", let, false},
		{"bob", refused(notInstalled), false},
		{"bob", Outcome{Verdict: Unserved, Status: http.StatusNotFound, Reason: "no module serves /store.v1.Store/Ping"}, false},
	} {
		want, stated := ping.Want[tc.person]
		if !stated {
			t.Fatalf("the row states nothing for %s", tc.person)
		}
		if problem := want.problem(tc.got); (problem == "") != tc.holds {
			t.Errorf("Ping as %s, answered %s %q: problem %q, want it to hold: %v", tc.person, tc.got.Verdict, tc.got.Reason, problem, tc.holds)
		}
	}

	// A role that carries nothing through the binding reaches the module for
	// nobody: its holder is issued nothing there, and told so.
	rows := notebookRows()
	rows[2].User = roleplan.RefusedAtBinding
	plan, published = planned(t, rows...)
	ping = derived(t, plan, published, "store store.v1.Store/Ping")
	nothing := refused(`the authority refused this person at store: carol holds nothing at store through binding "store"`)
	if problem := ping.Want["carol"].problem(nothing); problem != "" {
		t.Errorf("a role carrying nothing through the binding: %s", problem)
	}
	if problem := ping.Want["carol"].problem(let); problem == "" {
		t.Error("a role carrying nothing through the binding is let through, and the row holds")
	}
	read := derived(t, plan, published, "store store.v1.Store/Read")
	if problem := read.Want["carol"].problem(nothing); problem != "" {
		t.Errorf("a role carrying nothing through the binding, on a method that requires: %s", problem)
	}
}

// What the plan cannot be held to is said, not guessed: a procedure no row
// covers is not called, and a stage no page call is refused by is an error.
func TestWhatAPlanDoesNotStateIsNotDerived(t *testing.T) {
	plan, published := planned(t, notebookRows()...)
	rows, err := PlanRows(plan, cast, published)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(rows, func(r Row) bool { return r.Procedure == "store.v1.Store/Purge" }) {
		t.Error("a procedure no row of the plan covers is called")
	}
	bad := notebookRows()
	bad[3].User = roleplan.RefusedByPolicy
	plan, published = planned(t, bad...)
	if _, err := PlanRows(plan, cast, published); err == nil {
		t.Error("a page call the plan says the product's method policy refuses derives rows")
	}
	bad = notebookRows()
	bad[0].None = 0
	plan, published = planned(t, bad...)
	if _, err := PlanRows(plan, cast, published); err == nil {
		t.Error("a row stating no verdict derives rows")
	}
}

// What a published method carries (authority.hop.v1.Policy.carries) is nothing
// its hop requires: the calls a plan derives, and what each seat is expected
// on each, are the same with it as without. A seat is not refused for lacking
// what a method carries, nor let through for holding it.
func TestWhatAPublishedMethodCarriesChangesNoDerivedVerdict(t *testing.T) {
	plan, published := planned(t, notebookRows()...)
	carrying := Published{"store": maps.Clone(published["store"])}
	for procedure, declared := range carrying["store"] {
		if !declared.AnyCheckedCaller {
			// The read carries the write the user does not hold; every method
			// carries a purge no row asks.
			declared.Carries = []policy.Permission{{Kind: "store.item", Action: "write"}, {Kind: "store.item", Action: "purge"}}
			carrying["store"][procedure] = declared
		}
	}
	want, err := PlanRows(plan, cast, published)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PlanRows(plan, cast, carrying)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || len(want) == 0 {
		t.Fatalf("the plan derives %d rows with what its methods carry and %d without", len(got), len(want))
	}
	said := func(e Expect) string {
		return fmt.Sprintf("%v %q %q %q %q", e.verdict, e.stage, e.among, e.unmet, e.not)
	}
	for i, row := range want {
		if got[i].Name != row.Name || got[i].Call != row.Call {
			t.Fatalf("row %d is %q (%+v) with what its methods carry, %q (%+v) without", i, got[i].Name, got[i].Call, row.Name, row.Call)
		}
		for person, expect := range row.Want {
			if said(got[i].Want[person]) != said(expect) {
				t.Errorf("%s as %s: expected %s with what the method carries, %s without", row.Name, person, said(got[i].Want[person]), said(expect))
			}
		}
	}
	read := derived(t, plan, carrying, "store store.v1.Store/Read").Want["carol"]
	if read.verdict != Admit.verdict {
		t.Errorf("the user, who holds the read and not the write it carries, is expected %s", said(read))
	}
}
