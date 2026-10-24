package state_test

import (
	"errors"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

func reads(kind string) state.MethodPolicy {
	return state.MethodPolicy{Requires: []*basev0.WorkScopeV1{{ResourceKind: kind, Actions: []string{"read"}}}}
}

// A module serving HTTP declares routes, "<VERB> <template>"; a request
// "<VERB> <path>" is admitted under the route its path is an instance of, each
// "{name}" standing for a segment's text. A path no route matches is not
// served, and two matching routes are refused rather than guessed between.
func TestAnHTTPRequestIsAdmittedUnderTheRouteItsPathMatches(t *testing.T) {
	k := testkit.New(t)
	m := state.Manifest{Module: "gauge", Principal: "gauge", Kind: "module", Generation: 1, Bindings: map[string]state.Binding{},
		Methods: map[string]state.MethodPolicy{
			"GET /v1/gauge/profiles":                   reads("gauge.profiles"),
			"GET /v1/gauge/profiles/{ref}":             reads("gauge.profiles"),
			"POST /v1/gauge/matches/{match_id}:settle": {Requires: []*basev0.WorkScopeV1{{ResourceKind: "gauge.profiles", Actions: []string{"write"}}}},
			"GET /v1/gauge/{a}/x":                      {AnyCheckedCaller: true},
			"GET /v1/gauge/{b}/x":                      {AnyCheckedCaller: true},
		}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	read := []*basev0.WorkScopeV1{{ResourceKind: "gauge.profiles", Actions: []string{"read"}}}
	for request, want := range map[string]error{
		"GET /v1/gauge/profiles":             nil,
		"GET /v1/gauge/profiles/pro-1":       nil,
		"POST /v1/gauge/matches/m-1:settle":  state.ErrForbidden, // matched, but write is not held
		"GET /v1/gauge/profiles/pro-1/extra": state.ErrUnknown,
		"DELETE /v1/gauge/profiles/pro-1":    state.ErrUnknown,
		"POST /v1/gauge/matches/:settle":     state.ErrUnknown, // a {name} is never empty
		"GET /v1/gauge/ambiguous/x":          state.ErrForbidden,
	} {
		err := k.State.AdmitMethod("gauge", request, read)
		if (want == nil) != (err == nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v, want %v", request, err, want)
		}
	}
}
