package issuer_test

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

var updatePythonClaims = flag.Bool("update-python-claims", false, "regenerate Python claim projection fixtures through Core")

type claimProbe struct {
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	Allowed    bool   `json:"allowed"`
}

type claimProjection struct {
	Name     string                `json:"name"`
	Token    string                `json:"token"`
	Audience string                `json:"audience"`
	Scopes   []*basev0.WorkScopeV1 `json:"scopes"`
	Probes   []claimProbe          `json:"probes"`
}

// Python projects tokens minted and verified by Core. The clock is deliberately
// fixed: this tests wire/scope interpretation, not current token validity.
func TestPythonClaimProjectionFixtures(t *testing.T) {
	now := time.Unix(1792893600, 0)
	path := filepath.Join("..", "..", "..", "..", "..", "..", "..", "..", "libraries", "authority-client", "testdata", "claims.json")
	if *updatePythonClaims {
		fixtures, err := workcontext.Fixtures(now)
		if err != nil {
			t.Fatal(err)
		}
		var projections []claimProjection
		for _, fixture := range fixtures {
			if fixture.Outcome != workcontext.OutcomeAccepted {
				continue
			}
			projections = append(projections, coreProjection(t, now, fixture.Name, fixture.Token))
		}
		data, err := json.MarshalIndent(projections, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var projections []claimProjection
	if err := json.Unmarshal(data, &projections); err != nil {
		t.Fatal(err)
	}
	if len(projections) < 5 {
		t.Fatal("missing Core token forms")
	}
	for _, projection := range projections {
		t.Run(projection.Name, func(t *testing.T) {
			got := coreProjection(t, now, projection.Name, projection.Token)
			// JSON round-trip removes protobuf runtime internals from comparison.
			wantJSON, _ := json.Marshal(projection)
			gotJSON, _ := json.Marshal(got)
			if !reflect.DeepEqual(wantJSON, gotJSON) {
				t.Fatal("Core projection differs from shared fixture")
			}
		})
	}
}

func coreProjection(t *testing.T, now time.Time, name, token string) claimProjection {
	t.Helper()
	replay := workcontext.NewMemoryReplayStore()
	replay.Now = func() time.Time { return now }
	verifier := workcontext.Verifier{
		TrustTheConformanceFixtureKey: true,
		Issuer:                        workcontext.FixtureIssuer, Audience: workcontext.FixtureAudience,
		Keys: workcontext.FixtureKeys(), Revisions: workcontext.FixtureRevisions(),
		Replay: replay, Grants: workcontext.FixtureGrants(now), Seals: workcontext.FixtureSeals(),
		Now: func() time.Time { return now },
	}
	verified, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	scopes := verified.EffectiveScopes()
	projection := claimProjection{Name: name, Token: token, Audience: workcontext.FixtureAudience, Scopes: scopes}
	for _, scope := range scopes {
		for _, action := range append(append([]string{}, scope.GetActions()...), "undeclared") {
			for _, id := range append(append([]string{"", "other-resource"}, scope.GetResourceIds()...), "record-conformance") {
				ask := &basev0.WorkScopeV1{ResourceKind: scope.GetResourceKind(), Actions: []string{action}}
				if id != "" {
					ask.ResourceIds = []string{id}
				}
				allowed := false
				for _, candidate := range scopes {
					if workcontext.ScopeContained(ask, []*basev0.WorkScopeV1{candidate}) {
						allowed = true
						break
					}
				}
				projection.Probes = append(projection.Probes, claimProbe{scope.GetResourceKind(), action, id, allowed})
			}
		}
	}
	return projection
}
