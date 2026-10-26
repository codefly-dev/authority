package scope_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func sc(kind, owner string, actions []string, ids ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceIds: ids, ResourceOwnerId: owner}
}

func TestOwnerIsANarrowing(t *testing.T) {
	read := []string{"read"}
	for name, tc := range map[string]struct {
		narrow, wide []*basev0.WorkScopeV1
		attenuates   bool
	}{
		"the same owner":                {[]*basev0.WorkScopeV1{sc("doc", "u", read)}, []*basev0.WorkScopeV1{sc("doc", "u", read)}, true},
		"an owner added to a whole kind": {[]*basev0.WorkScopeV1{sc("doc", "u", read)}, []*basev0.WorkScopeV1{sc("doc", "", read)}, true},
		"ids within the owner":          {[]*basev0.WorkScopeV1{sc("doc", "u", read, "a")}, []*basev0.WorkScopeV1{sc("doc", "u", read)}, true},
		"another owner":                 {[]*basev0.WorkScopeV1{sc("doc", "v", read)}, []*basev0.WorkScopeV1{sc("doc", "u", read)}, false},
		"the owner dropped":             {[]*basev0.WorkScopeV1{sc("doc", "", read)}, []*basev0.WorkScopeV1{sc("doc", "u", read)}, false},
		"an id without its owner":       {[]*basev0.WorkScopeV1{sc("doc", "", read, "a")}, []*basev0.WorkScopeV1{sc("doc", "u", read)}, false},
		"the owner's ids widened":       {[]*basev0.WorkScopeV1{sc("doc", "u", read)}, []*basev0.WorkScopeV1{sc("doc", "u", read, "a")}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := scope.Attenuates(tc.narrow, tc.wide); got != tc.attenuates {
				t.Fatalf("Attenuates = %v", got)
			}
		})
	}
}

func TestIntersectKeepsTheNarrowerOwner(t *testing.T) {
	got := scope.Intersect([]*basev0.WorkScopeV1{sc("doc", "", []string{"read", "write"})}, []*basev0.WorkScopeV1{sc("doc", "u", []string{"read"})})
	if len(got) != 1 || got[0].GetResourceOwnerId() != "u" || len(got[0].GetActions()) != 1 {
		t.Fatalf("got %v", got)
	}
	if got := scope.Intersect([]*basev0.WorkScopeV1{sc("doc", "v", []string{"read"})}, []*basev0.WorkScopeV1{sc("doc", "u", []string{"read"})}); len(got) != 0 {
		t.Fatalf("two owners met as %v", got)
	}
	owned := scope.Owned([]*basev0.WorkScopeV1{sc("doc", "", []string{"read"})}, "u")
	if owned[0].GetResourceOwnerId() != "u" || !scope.HasOwner(owned) {
		t.Fatalf("owned %v", owned)
	}
}
