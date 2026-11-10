package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Rob reads entry-x alone through his organization role at the ledger, which
// checks no owner. What he is issued, and every hop below it, names entry-x and
// nothing else of the kind: a module deciding from the token's claims never
// sees the whole kind.
func TestAResourceScopedOrganizationRoleIssuesItsIDsAlone(t *testing.T) {
	h := newHarness(t)
	read := []string{"read"}
	ids := func(of ...string) *basev0.WorkScopeV1 { return owned(ledgerKind, "", read, of...) }

	root := h.must(h.root("rob", "ledger"))
	exactly(t, root, ledgerKind, "", read, "entry-x")
	if err := h.check(root); err != nil {
		t.Fatal(err)
	}
	grants, err := h.svc.ListResources(h.ctx, root.Token, "ledger", ledgerKind, "read")
	if err != nil || len(grants) != 1 || grants[0].ID != "entry-x" {
		t.Fatalf("listed %v %v", grants, err)
	}

	for name, ask := range map[string]*basev0.WorkScopeV1{
		"another id":         ids("entry-y"),
		"a held and another": ids("entry-x", "entry-y"),
		"the whole kind":     sc(ledgerKind, "read"),
	} {
		t.Run("an ask naming "+name+" is refused", func(t *testing.T) {
			_, err := h.root("rob", "ledger", ask)
			refused(t, err, "widens")
		})
		t.Run("a child naming "+name+" is refused", func(t *testing.T) {
			_, err := h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self", Scopes: []*basev0.WorkScopeV1{ask}})
			refused(t, err, "widens")
		})
	}
	exactly(t, h.must(h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self"})), ledgerKind, "", read, "entry-x")
	exactly(t, h.must(h.root("rob", "ledger", ids("entry-x"))), ledgerKind, "", read, "entry-x")
}
