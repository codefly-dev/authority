package roleplan_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/roleplan"
)

// A solution with its own kind, one binding to a store, and the two roles:
// the admin reads, writes and uploads into the store, and reads the archive
// the store reaches in turn; the user reads.
const contract = `schema: codefly/module-contract/v1
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
          - resource_kind: archive.item
            actions: [read]
            through: store
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

// product is the notebook as its repository lays it out: the contract at its
// root and the composition's configurations beside it.
func product(t *testing.T, c string) roleplan.Product {
	t.Helper()
	dir := t.TempDir()
	configs := filepath.Join(dir, "configurations", "local")
	if err := os.MkdirAll(configs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.contract.codefly.yaml"), []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configs, "notebook-audiences.env"), []byte("store-audience=store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return roleplan.Product{
		Dir:            dir,
		Name:           "notebook",
		Configurations: configs,
		Kind:           domain.KindSolution,
		Methods: map[string]roleplan.Policy{
			"GET /v1/notebook/notes":       {Requires: []string{"notebook.note:read"}},
			"POST /v1/notebook/notes":      {Requires: []string{"notebook.note:write"}},
			"POST /v1/notebook/store/read": {Requires: []string{"notebook.note:read"}},
			"POST /v1/notebook/store/put":  {Requires: []string{"notebook.note:write"}},
			"GET /v1/notebook/elsewhere":   {AnyCheckedCaller: true},
		},
	}
}

func rows() []roleplan.Row {
	A, N, P, B := roleplan.Allowed, roleplan.RefusedNoRole, roleplan.RefusedByPolicy, roleplan.RefusedAtBinding
	return []roleplan.Row{
		{Name: "read notes", Method: "GET /v1/notebook/notes", Admin: A, User: A, None: N},
		{Name: "write a note", Method: "POST /v1/notebook/notes", Admin: A, User: P, None: N},
		{Name: "read the store", Method: "POST /v1/notebook/store/read", Binding: "store", Asks: []string{"store.item:read"}, Admin: A, User: A, None: N},
		{Name: "put into the store", Method: "POST /v1/notebook/store/put", Binding: "store", Asks: []string{"store.item:write"}, Admin: A, User: P, None: N},
		{Name: "reach a route refused downstream", Method: "GET /v1/notebook/elsewhere", Admin: A, User: A, None: N},
		{Name: "the page reads the store", Binding: "store", Asks: []string{"store.item:read"}, Admin: A, User: A, None: N},
		{Name: "the page writes the store", Binding: "store", Asks: []string{"store.item:write"}, Admin: A, User: B, None: N},
		{Name: "the page reads the archive through the store", Binding: "store", Asks: []string{"store.item:read"}, Onward: []string{"archive.item:read"},
			Admin: A, User: roleplan.RefusedOnward, None: N},
		{Name: "administer the installation", Administer: true, Admin: A, User: roleplan.RefusedAdminister, None: roleplan.RefusedAdminister},
	}
}

func TestAPlanTheAuthorityFollowsHolds(t *testing.T) {
	roleplan.Assert(t, roleplan.Plan{Product: product(t, contract), Rows: rows()})
}

// problems runs a plan expected to fail and requires each of want among its
// problems.
func problems(t *testing.T, plan roleplan.Plan, want ...string) {
	t.Helper()
	got := roleplan.Problems(plan)
	for _, w := range want {
		if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, w) }) {
			t.Errorf("want a problem naming %q, got %q", w, got)
		}
	}
	if len(got) == 0 {
		t.Error("the plan holds; it must not")
	}
}

// Granting the user write: the authority now lets it write, which the plan
// refuses, and every refusal it still gives names its reason.
func TestARoleGrantingMoreThanThePlanFails(t *testing.T) {
	widened := strings.Replace(contract, `          - resource_kind: notebook.note
            actions: [read]
          - resource_kind: store.item
            actions: [read]`, `          - resource_kind: notebook.note
            actions: [read, write]
          - resource_kind: store.item
            actions: [read, write]`, 1)
	problems(t, roleplan.Plan{Product: product(t, widened), Rows: rows()},
		`"write a note": user-holder is allowed, the plan says refused by the method policy`,
		`"put into the store": user-holder is allowed, the plan says refused by the method policy`)
}

func TestARoleGrantingLessThanThePlanFails(t *testing.T) {
	r := rows()
	r[1].User = roleplan.Allowed
	problems(t, roleplan.Plan{Product: product(t, contract), Rows: r},
		`"write a note": user-holder is refused by the method policy, the plan says allowed: notebook requires notebook.note:write`)
}

func TestAMethodWithoutARowFails(t *testing.T) {
	p := product(t, contract)
	p.Methods["DELETE /v1/notebook/notes"] = roleplan.Policy{Requires: []string{"notebook.note:write"}}
	problems(t, roleplan.Plan{Product: p, Rows: rows()}, "notebook serves DELETE /v1/notebook/notes, which 0 rows of the plan name")
}

func TestARowNamingNoMethodFails(t *testing.T) {
	r := append(rows(), roleplan.Row{Name: "gone", Method: "GET /v1/notebook/gone", Admin: roleplan.Allowed, User: roleplan.RefusedByPolicy, None: roleplan.RefusedNoRole})
	problems(t, roleplan.Plan{Product: product(t, contract), Rows: r}, `"gone" names GET /v1/notebook/gone, which notebook does not serve`)
}

func TestABindingPermissionNoRowAsksForFails(t *testing.T) {
	r := slices.DeleteFunc(rows(), func(r roleplan.Row) bool { return slices.Contains(r.Asks, "store.item:write") })
	problems(t, roleplan.Plan{Product: product(t, contract), Rows: r}, `binding "store" carries store.item:write for a person, which no row of the plan asks for`)
}

// Least privilege: the user holds write on its own kind, and no row lets it
// write, so the grant is unused authority.
func TestAnUnusedGrantFails(t *testing.T) {
	widened := strings.Replace(contract, `          - resource_kind: notebook.note
            actions: [read]`, `          - resource_kind: notebook.note
            actions: [read, write]`, 1)
	r := slices.DeleteFunc(rows(), func(r roleplan.Row) bool { return r.Name == "the page writes the store" })
	r[1].User, r[3].User = roleplan.RefusedByPolicy, roleplan.RefusedByPolicy
	got := roleplan.Problems(roleplan.Plan{Product: product(t, widened), Rows: r})
	if !slices.ContainsFunc(got, func(p string) bool {
		return strings.Contains(p, "role user grants notebook.note:write, which no row its holder is allowed uses the way it is granted")
	}) {
		t.Fatalf("want the unused grant named, got %q", got)
	}
}

func TestAMissingVerdictFails(t *testing.T) {
	r := rows()
	r[0].None = 0
	problems(t, roleplan.Plan{Product: product(t, contract), Rows: r}, `"read notes": the plan states no verdict for no-role`)
}

// The user names nothing through the store, so the authority carries none of
// the archive onward for it.
func TestWhatARoleCarriesOnwardIsTheAuthoritys(t *testing.T) {
	r := rows()
	r[7].User = roleplan.Allowed
	problems(t, roleplan.Plan{Product: product(t, contract), Rows: r},
		`"the page reads the archive through the store": user-holder is refused onward, the plan says allowed: carrying archive.item:read onward through binding "store"`)
}

// A route whose policy stops refusing is red even when a later decision still
// refuses the subject: the plan names the refuser, and it moved.
func TestARefusalThatMovesFails(t *testing.T) {
	p := product(t, contract)
	p.Methods["POST /v1/notebook/store/put"] = roleplan.Policy{Requires: []string{"notebook.note:read"}}
	problems(t, roleplan.Plan{Product: p, Rows: rows()},
		`"put into the store": user-holder is refused at the binding, the plan says refused by the method policy`)
	p.Methods["POST /v1/notebook/store/put"] = roleplan.Policy{AnyCheckedCaller: true}
	problems(t, roleplan.Plan{Product: p, Rows: rows()},
		`"put into the store": user-holder is refused at the binding, the plan says refused by the method policy`)
}

// A grant counts only through the binding it was granted on: the admin's
// archive grant is named through the store, and a row going onward through
// another way does not use it.
func TestAGrantUsedThroughAnotherWayIsUnused(t *testing.T) {
	r := slices.DeleteFunc(rows(), func(r roleplan.Row) bool { return len(r.Onward) > 0 })
	r = append(r, roleplan.Row{Name: "the archive asked for, not reached onward", Method: "", Binding: "store", Asks: []string{"store.item:read"},
		Admin: roleplan.Allowed, User: roleplan.Allowed, None: roleplan.RefusedNoRole})
	problems(t, roleplan.Plan{Product: product(t, contract), Rows: r},
		"role admin grants archive.item:read, which no row its holder is allowed uses the way it is granted")
}

// The render's refusals are the plan's: a contract naming another principal.
func TestTheRendersRefusalsHold(t *testing.T) {
	p := product(t, contract)
	p.Name = "journal"
	problems(t, roleplan.Plan{Product: p, Rows: rows()}, `module journal publishes a contract whose principal is "notebook"`)
}
