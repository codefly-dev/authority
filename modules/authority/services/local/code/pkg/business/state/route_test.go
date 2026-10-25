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
			"GET /v1/gauge/sources/{repo=**}":          reads("gauge.profiles"),
			"POST /v1/gauge/sources/{repo=**}:settle":  reads("gauge.profiles"),
			"/gauge.v1.GaugeService/ListProfiles":      reads("gauge.profiles"),
		}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	read := []*basev0.WorkScopeV1{{ResourceKind: "gauge.profiles", Actions: []string{"read"}}}
	for request, want := range map[string]error{
		"GET /v1/gauge/profiles":                             nil,
		"GET /v1/gauge/profiles/pro-1":                       nil,
		"POST /v1/gauge/matches/m-1:settle":                  state.ErrForbidden, // matched, but write is not held
		"GET /v1/gauge/profiles/pro-1/extra":                 state.ErrUnknown,
		"DELETE /v1/gauge/profiles/pro-1":                    state.ErrUnknown,
		"POST /v1/gauge/matches/:settle":                     state.ErrUnknown, // a {name} is never empty
		"GET /v1/gauge/ambiguous/x":                          state.ErrForbidden,
		"GET /v1/gauge/sources/github.com/acme/repo":         nil, // {repo=**} takes the rest of the path
		"GET /v1/gauge/sources/":                             state.ErrUnknown,
		"POST /v1/gauge/sources/github.com/acme/repo:settle": nil, // the verb after the rest of the path
		"POST /v1/gauge/sources/:settle":                     state.ErrUnknown,
		"POST /gauge.v1.GaugeService/ListProfiles":           nil, // a Connect call is its method
		"GET /gauge.v1.GaugeService/ListProfiles":            state.ErrUnknown,
	} {
		err := k.State.AdmitMethod("gauge", request, read)
		if (want == nil) != (err == nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v, want %v", request, err, want)
		}
	}
}

// A module the fixture stands in for (one a local run supervises itself) is
// replaced by the module's own delivery, whatever generation the delivery
// carries; a delivered module is not replaced by a stale one.
func TestADeliveryReplacesTheFixturesStandIn(t *testing.T) {
	k := testkit.New(t)
	standIn := state.Manifest{Module: "gauge", Principal: "gauge", Kind: "module", Generation: 1, Bindings: map[string]state.Binding{}, StandIn: true}
	if _, err := k.State.ApplyManifest(standIn); err != nil {
		t.Fatal(err)
	}
	delivered := state.Manifest{Module: "gauge", Principal: "gauge", Kind: "module", Generation: 1, Bindings: map[string]state.Binding{},
		Methods: map[string]state.MethodPolicy{"GET /v1/gauge/profiles": reads("gauge.profiles")}}
	if _, err := k.State.ApplyManifest(delivered); err != nil {
		t.Fatalf("the module's own delivery did not replace the stand-in: %v", err)
	}
	if _, err := k.State.ApplyManifest(delivered); !errors.Is(err, state.ErrStale) {
		t.Fatalf("a delivered module took a manifest of the same generation: %v", err)
	}
}
