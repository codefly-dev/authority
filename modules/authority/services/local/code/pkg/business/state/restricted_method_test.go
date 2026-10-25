package state_test

import (
	"errors"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func TestMethodAdmissionNeverWidensResourceRestrictedScopes(t *testing.T) {
	k := testkit.New(t)
	m := state.Manifest{Module: "gauge", Principal: "gauge", Kind: "module", Generation: 1,
		Methods: map[string]state.MethodPolicy{
			"/gauge.Service/List": reads("gauge.items"),
			"/gauge.Service/Edit": {Requires: []*basev0.WorkScopeV1{scope("gauge.items", nil, "read", "write")}},
			"/gauge.Service/Ping": {AnyCheckedCaller: true},
		}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method string
		held         []*basev0.WorkScopeV1
		allow        bool
	}{
		{"one resource", "List", []*basev0.WorkScopeV1{scope("gauge.items", []string{"one"}, "read")}, false},
		{"several resource scopes", "List", []*basev0.WorkScopeV1{scope("gauge.items", []string{"one"}, "read"), scope("gauge.items", []string{"two"}, "read")}, false},
		{"restricted wildcard", "List", []*basev0.WorkScopeV1{scope("gauge.items", []string{"one"}, state.AnyAction)}, false},
		{"whole kind", "List", []*basev0.WorkScopeV1{scope("gauge.items", nil, "read")}, true},
		{"whole wildcard", "Edit", []*basev0.WorkScopeV1{scope("gauge.items", nil, state.AnyAction)}, true},
		{"whole wildcard alongside restricted action", "List", []*basev0.WorkScopeV1{scope("gauge.items", nil, state.AnyAction), scope("gauge.items", []string{"one"}, "read")}, true},
		{"whole read restricted write", "Edit", []*basev0.WorkScopeV1{scope("gauge.items", nil, "read"), scope("gauge.items", []string{"one"}, "write")}, false},
		{"whole grant alongside restricted", "List", []*basev0.WorkScopeV1{scope("gauge.items", []string{"one"}, "read"), scope("gauge.items", nil, "read")}, true},
		{"checked caller", "Ping", []*basev0.WorkScopeV1{scope("gauge.items", []string{"one"}, "read")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := k.State.AdmitMethod("gauge", "/gauge.Service/"+tc.method, tc.held)
			if tc.allow {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, state.ErrForbidden) {
				t.Fatalf("got %v, want forbidden", err)
			}
			if !strings.Contains(err.Error(), "resource-limited") {
				t.Fatalf("diagnostic hides the resource restriction: %v", err)
			}
		})
	}
}
