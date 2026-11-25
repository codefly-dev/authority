package scope_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"
)

func sc(kind, owner string, actions []string, ids ...string) *basev1.WorkScopeV1 {
	return &basev1.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceIds: ids, ResourceOwnerId: owner}
}

func TestOwnerIsANarrowing(t *testing.T) {
	read := []string{"read"}
	for name, tc := range map[string]struct {
		narrow, wide []*basev1.WorkScopeV1
		attenuates   bool
	}{
		"the same owner":                 {[]*basev1.WorkScopeV1{sc("doc", "u", read)}, []*basev1.WorkScopeV1{sc("doc", "u", read)}, true},
		"an owner added to a whole kind": {[]*basev1.WorkScopeV1{sc("doc", "u", read)}, []*basev1.WorkScopeV1{sc("doc", "", read)}, true},
		"ids within the owner":           {[]*basev1.WorkScopeV1{sc("doc", "u", read, "a")}, []*basev1.WorkScopeV1{sc("doc", "u", read)}, true},
		"another owner":                  {[]*basev1.WorkScopeV1{sc("doc", "v", read)}, []*basev1.WorkScopeV1{sc("doc", "u", read)}, false},
		"the owner dropped":              {[]*basev1.WorkScopeV1{sc("doc", "", read)}, []*basev1.WorkScopeV1{sc("doc", "u", read)}, false},
		"an id without its owner":        {[]*basev1.WorkScopeV1{sc("doc", "", read, "a")}, []*basev1.WorkScopeV1{sc("doc", "u", read)}, false},
		"the owner's ids widened":        {[]*basev1.WorkScopeV1{sc("doc", "u", read)}, []*basev1.WorkScopeV1{sc("doc", "u", read, "a")}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := scope.Attenuates(tc.narrow, tc.wide); got != tc.attenuates {
				t.Fatalf("Attenuates = %v", got)
			}
		})
	}
}

func TestIntersectKeepsTheNarrowerOwner(t *testing.T) {
	got := scope.Intersect([]*basev1.WorkScopeV1{sc("doc", "", []string{"read", "write"})}, []*basev1.WorkScopeV1{sc("doc", "u", []string{"read"})})
	if len(got) != 1 || got[0].GetResourceOwnerId() != "u" || len(got[0].GetActions()) != 1 {
		t.Fatalf("got %v", got)
	}
	if got := scope.Intersect([]*basev1.WorkScopeV1{sc("doc", "v", []string{"read"})}, []*basev1.WorkScopeV1{sc("doc", "u", []string{"read"})}); len(got) != 0 {
		t.Fatalf("two owners met as %v", got)
	}
	owned, err := scope.Owned([]*basev1.WorkScopeV1{sc("doc", "", []string{"read"})}, "u")
	if err != nil || owned[0].GetResourceOwnerId() != "u" || !scope.HasOwner(owned) {
		t.Fatalf("owned %v, %v", owned, err)
	}
	if got, err := scope.Owned([]*basev1.WorkScopeV1{sc("doc", "", []string{"read"})}, ""); err == nil || got != nil {
		t.Fatalf("an empty owner rendered %v", got)
	}
}
