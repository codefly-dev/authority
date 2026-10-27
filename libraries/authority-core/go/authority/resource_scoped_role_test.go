package authority_test

import (
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// Rob reads store-x alone through his organization role. What he is issued,
// and every hop below it, names store-x and nothing else of the kind: a
// module deciding from the token's claims never sees the whole kind.
func TestAResourceScopedOrganizationRoleIssuesItsIDsAlone(t *testing.T) {
	h := newHarness(t)
	read := []string{"read"}
	ids := func(of ...string) *basev0.WorkScopeV1 { return owned(kind, "", read, of...) }

	root := h.must(h.root("rob", "store"))
	exactly(t, root, kind, "", read, "store-x")
	if err := h.check(root); err != nil {
		t.Fatal(err)
	}
	grants, err := h.svc.ListResources(h.ctx, root.Token, "store", kind, "read")
	if err != nil || len(grants) != 1 || grants[0].ID != "store-x" {
		t.Fatalf("listed %v %v", grants, err)
	}

	for name, ask := range map[string]*basev0.WorkScopeV1{
		"another id":         ids("store-y"),
		"a held and another": ids("store-x", "store-y"),
		"the whole kind":     sc(kind, "read"),
	} {
		t.Run("an ask naming "+name+" is refused", func(t *testing.T) {
			_, err := h.root("rob", "store", ask)
			refused(t, err, "widens")
		})
		t.Run("a child naming "+name+" is refused", func(t *testing.T) {
			_, err := h.hop(root, "self", ask)
			refused(t, err, "widens")
		})
	}
	exactly(t, h.must(h.hop(root, "self")), kind, "", read, "store-x")
	exactly(t, h.must(h.root("rob", "store", ids("store-x"))), kind, "", read, "store-x")
}
