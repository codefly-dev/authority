package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"

	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

// Rob is a user of the ledger's page and asks for entry-x alone. What he is
// issued, and every hop below it, names entry-x and nothing else of the kind:
// a module deciding from the token's claims never sees the whole kind, and no
// hop widens back to what his role holds.
func TestACapabilityNarrowedToIDsCarriesThemAlone(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ledgerWithRoles(t, h, "rob")
	read := []string{"read"}
	ids := func(of ...string) *basev1.WorkScopeV1 { return owned(ledgerKind, "", read, of...) }

	root := h.must(h.root("rob", "ledger", ids("entry-x")))
	exactly(t, root, ledgerKind, "", read, "entry-x")
	if err := h.check(root); err != nil {
		t.Fatal(err)
	}
	grants, err := h.svc.ListResources(h.ctx, root.Token, "ledger", ledgerKind, "read")
	if err != nil || len(grants) != 1 || grants[0].ID != "entry-x" {
		t.Fatalf("listed %v %v", grants, err)
	}

	for name, ask := range map[string]*basev1.WorkScopeV1{
		"another id":         ids("entry-y"),
		"a held and another": ids("entry-x", "entry-y"),
		"the whole kind":     sc(ledgerKind, "read"),
	} {
		t.Run("a child naming "+name+" is refused", func(t *testing.T) {
			_, err := h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self", Scopes: []*basev1.WorkScopeV1{ask}})
			refused(t, err, "widens")
		})
	}
	exactly(t, h.must(h.svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self"})), ledgerKind, "", read, "entry-x")
}
