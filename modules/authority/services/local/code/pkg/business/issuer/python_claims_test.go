package issuer_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/protobuf/proto"
)

var updatePythonClaims = flag.Bool("update-python-claims", false, "regenerate Python claim projection fixtures through Core")

type claimProbe struct {
	Kind       string `json:"kind"`
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	// Owner, when set, is the resource's owner: the owner-aware question
	// (AllowsOwned); without it the probe is the owner-blind Allows.
	Owner   *string `json:"owner,omitempty"`
	Allowed bool    `json:"allowed"`
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
			if fixture.Name == "session" {
				projections = append(projections, coreProjection(t, now, "owner-selected", ownerSelected(t, fixture.Token)))
			}
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
	owned := slices.ContainsFunc(scopes, func(s *basev0.WorkScopeV1) bool { return s.GetResourceOwnerId() != "" })
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
				projection.Probes = append(projection.Probes, claimProbe{scope.GetResourceKind(), action, id, nil, allowed})
				if !owned {
					continue
				}
				for _, owner := range []string{fixtureOwner, "principal-other", ""} {
					ask := proto.CloneOf(ask)
					ask.ResourceOwnerId = owner
					allowed := slices.ContainsFunc(scopes, func(c *basev0.WorkScopeV1) bool { return workcontext.ScopeContained(ask, []*basev0.WorkScopeV1{c}) })
					projection.Probes = append(projection.Probes, claimProbe{scope.GetResourceKind(), action, id, &owner, allowed})
				}
			}
		}
	}
	return projection
}

// fixtureOwner is the principal the owner-selected fixture's scopes select.
const fixtureOwner = "principal-u"

// ownerSelected is Core's session fixture with owner-selected scopes beside a
// plain one, signed with Core's fixture key: the shape a capability issued
// through a solution carries, which every reader must answer alike.
func ownerSelected(t *testing.T, session string) string {
	t.Helper()
	decoded, err := workcontext.Decode(session)
	if err != nil {
		t.Fatal(err)
	}
	c := decoded.Context()
	c.AuthorityScopes = []*basev0.WorkScopeV1{
		{ResourceKind: "record", Actions: []string{"read"}, ResourceOwnerId: fixtureOwner},
		{ResourceKind: "note", Actions: []string{"read"}, ResourceIds: []string{"n1"}, ResourceOwnerId: fixtureOwner},
		{ResourceKind: "plain", Actions: []string{"read"}},
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	_, key := workcontext.FixtureKeyPair()
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, body))
}
