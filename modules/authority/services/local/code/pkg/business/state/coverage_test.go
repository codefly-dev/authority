package state_test

import (
	"testing"

	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"

	"gateway/pkg/business/state"
)

func scope(kind string, ids []string, actions ...string) *basev1.WorkScopeV1 {
	return &basev1.WorkScopeV1{ResourceKind: kind, Actions: actions, ResourceIds: ids}
}

func render(in []*basev1.WorkScopeV1) string {
	out := ""
	for _, sc := range in {
		out += sc.GetResourceKind() + "|"
		for _, a := range sc.GetActions() {
			out += a + ","
		}
		out += "|"
		for _, id := range sc.GetResourceIds() {
			out += id + ","
		}
		out += ";"
	}
	return out
}

// A scope limited to named resources is never widened to its kind: an ask for
// ids meets a whole-kind holding as those ids, two id sets meet as their common
// ids, and nothing in common is nothing.
func TestTheNarrowerSideWinsAndIDsAreNeverDropped(t *testing.T) {
	whole := []*basev1.WorkScopeV1{scope("documents.collection", nil, "read", "admin")}
	for name, c := range map[string]struct {
		asked []*basev1.WorkScopeV1
		held  []*basev1.WorkScopeV1
		want  string
	}{
		"ids within a whole kind": {[]*basev1.WorkScopeV1{scope("documents.collection", []string{"a", "b"}, "read")}, whole, "documents.collection|read,|a,b,;"},
		"a whole kind within ids": {whole, []*basev1.WorkScopeV1{scope("documents.collection", []string{"a"}, "read")}, "documents.collection|read,|a,;"},
		"common ids":              {[]*basev1.WorkScopeV1{scope("documents.collection", []string{"a", "b"}, "read")}, []*basev1.WorkScopeV1{scope("documents.collection", []string{"b", "c"}, "read")}, "documents.collection|read,|b,;"},
		"no common id is nothing": {[]*basev1.WorkScopeV1{scope("documents.collection", []string{"a"}, "read")}, []*basev1.WorkScopeV1{scope("documents.collection", []string{"c"}, "read")}, ""},
		"an action not held":      {[]*basev1.WorkScopeV1{scope("documents.collection", []string{"a"}, "share")}, whole, ""},
	} {
		if got := render(state.Intersect(c.asked, c.held)); got != c.want {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
	if got := render(state.Normalize([]*basev1.WorkScopeV1{scope("k", []string{"b"}, "read"), scope("k", []string{"a"}, "read"), scope("k", nil, "write")})); got != "k|write,|;k|read,|a,b,;" {
		t.Errorf("normalize merges ids per action and keeps the whole kind apart: %q", got)
	}
	if got := render(state.Normalize([]*basev1.WorkScopeV1{scope("k", []string{"a"}, "read"), scope("k", nil, "read")})); got != "k|read,|;" {
		t.Errorf("a whole-kind holding of an action covers its ids: %q", got)
	}
}

func TestAttenuationSeesAWideningOfResources(t *testing.T) {
	ids := []*basev1.WorkScopeV1{scope("documents.collection", []string{"a"}, "read")}
	whole := []*basev1.WorkScopeV1{scope("documents.collection", nil, "read")}
	if !state.Attenuates(ids, whole) {
		t.Fatal("named ids attenuate the whole kind")
	}
	if state.Attenuates(whole, ids) {
		t.Fatal("the whole kind does not attenuate named ids")
	}
	if state.Attenuates([]*basev1.WorkScopeV1{scope("documents.collection", []string{"a", "z"}, "read")}, ids) {
		t.Fatal("an id beyond the holding does not attenuate it")
	}
}
