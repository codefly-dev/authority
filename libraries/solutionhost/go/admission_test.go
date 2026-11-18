package solutionhost_test

import (
	"context"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/codefly-dev/core/composition"
	"github.com/stretchr/testify/require"
)

func next(t *testing.T, change func(*solutionhost.ModuleManifest)) *solutionhost.ModuleManifest {
	t.Helper()
	manifest := valid(t)
	manifest.Generation++
	if change != nil {
		change(manifest)
	}
	return manifest
}

// The generation ladder a host walks for every delivered manifest, one rung
// per case: what it held for the binding, what arrived, and the answer.
func TestAdmitWalksTheGenerationLadder(t *testing.T) {
	for name, tc := range map[string]struct {
		previous  func(t *testing.T) *solutionhost.ModuleManifest
		candidate func(t *testing.T) *solutionhost.ModuleManifest
		decision  solutionhost.Decision
		refusal   error
	}{
		"a new binding is accepted": {
			previous: func(*testing.T) *solutionhost.ModuleManifest { return nil }, candidate: valid, decision: solutionhost.DecisionAccept,
		},
		"the applied manifest replays": {previous: valid, candidate: valid, decision: solutionhost.DecisionReplay},
		"a higher generation is accepted": {
			previous: valid, candidate: func(t *testing.T) *solutionhost.ModuleManifest { return next(t, nil) }, decision: solutionhost.DecisionAccept,
		},
		"a lower generation is stale": {
			previous: func(t *testing.T) *solutionhost.ModuleManifest { return next(t, nil) }, candidate: valid, refusal: solutionhost.ErrStaleGeneration,
		},
		"the same generation with other content is a rewrite": {
			previous: valid,
			candidate: func(t *testing.T) *solutionhost.ModuleManifest {
				manifest := valid(t)
				manifest.Endpoints[0].Address = "http://localhost:6000"
				return manifest
			},
			refusal: solutionhost.ErrRewrittenGeneration,
		},
		"a withdrawal at a higher generation is accepted": {previous: valid, candidate: removed, decision: solutionhost.DecisionAccept},
		"a withdrawal replays":                            {previous: removed, candidate: removed, decision: solutionhost.DecisionReplay},
		"a withdrawn binding never comes back": {
			previous: removed,
			candidate: func(t *testing.T) *solutionhost.ModuleManifest {
				return next(t, func(m *solutionhost.ModuleManifest) { m.Generation = removed(t).Generation + 1 })
			},
			refusal: solutionhost.ErrWithdrawn,
		},
		"a binding keeps its domain": {
			previous: valid,
			candidate: func(t *testing.T) *solutionhost.ModuleManifest {
				return next(t, func(m *solutionhost.ModuleManifest) { m.Host.Domain = "other" })
			},
			refusal: solutionhost.ErrWrongDomain,
		},
		"another domain cannot withdraw a binding": {
			previous: valid,
			candidate: func(t *testing.T) *solutionhost.ModuleManifest {
				manifest := removed(t)
				manifest.Host.Domain = "other"
				return manifest
			},
			refusal: solutionhost.ErrWrongDomain,
		},
		"a manifest for another host is refused": {
			previous: func(*testing.T) *solutionhost.ModuleManifest { return nil },
			candidate: func(t *testing.T) *solutionhost.ModuleManifest {
				return next(t, func(m *solutionhost.ModuleManifest) { m.Host.Coordinate = "obin/prod/eu" })
			},
			refusal: solutionhost.ErrWrongHost,
		},
		"a binding keeps its host": {
			previous: func(t *testing.T) *solutionhost.ModuleManifest {
				manifest := valid(t)
				manifest.Host.Coordinate = "obin/prod/eu"
				return manifest
			},
			candidate: func(t *testing.T) *solutionhost.ModuleManifest { return next(t, nil) },
			refusal:   solutionhost.ErrWrongHost,
		},
		"an invalid candidate is refused": {
			previous: valid,
			candidate: func(t *testing.T) *solutionhost.ModuleManifest {
				return next(t, func(m *solutionhost.ModuleManifest) { m.Workloads = nil })
			},
			refusal: solutionhost.ErrInvalid,
		},
		"the host's record for another binding is its own defect": {
			previous: func(t *testing.T) *solutionhost.ModuleManifest {
				manifest := valid(t)
				manifest.Binding = "acme.local.other"
				return manifest
			},
			candidate: valid,
			refusal:   solutionhost.ErrAppliedUnusable,
		},
		"an invalid applied record is the host's defect": {
			previous: func(t *testing.T) *solutionhost.ModuleManifest {
				manifest := valid(t)
				manifest.Generation = 0
				return manifest
			},
			candidate: valid,
			refusal:   solutionhost.ErrAppliedUnusable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := solutionhost.Admit(testCoordinate, tc.previous(t), tc.candidate(t))
			if tc.refusal != nil {
				require.ErrorIs(t, err, tc.refusal)
				require.Empty(t, decision)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.decision, decision)
		})
	}
	_, err := solutionhost.Admit("", nil, valid(t))
	require.ErrorIs(t, err, solutionhost.ErrInvalid, "a host admits under its own coordinate")
}

// What a host does end to end with a delivery: verify, then admit against
// what it holds. The decision is about the attested bytes, not about anything
// a caller held since.
func TestADeliveredManifestIsAdmittedFromItsAttestedBytes(t *testing.T) {
	delivered, err := solutionhost.VerifyDelivered(context.Background(), signedValid(t), testVerifier(t))
	require.NoError(t, err)
	held, err := delivered.Manifest()
	require.NoError(t, err)
	held.Generation = 1000 // a caller normalising its copy changes nothing
	candidate, err := delivered.Manifest()
	require.NoError(t, err)
	decision, err := solutionhost.Admit(testCoordinate, valid(t), candidate)
	require.NoError(t, err)
	require.Equal(t, solutionhost.DecisionReplay, decision)
}

func TestCheckAlias(t *testing.T) {
	other := func(t *testing.T, change func(*solutionhost.ModuleManifest)) *solutionhost.ModuleManifest {
		manifest := valid(t)
		manifest.Binding = "acme.local.notes"
		manifest.Alias = "notes"
		manifest.Workloads = manifest.Workloads[:1]
		manifest.Endpoints = manifest.Endpoints[:1]
		if change != nil {
			change(manifest)
		}
		return manifest
	}
	reserved := []string{"codefly"}

	require.NoError(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{other(t, nil)}, valid(t)))
	// Its own applied manifest is the one it replaces.
	require.NoError(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{valid(t)}, next(t, nil)))

	// Another live binding on the same host holds the alias.
	holder := other(t, func(m *solutionhost.ModuleManifest) { m.Alias = "wiki" })
	err := solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{holder}, valid(t))
	require.ErrorIs(t, err, composition.ErrCollision)

	// ... but not on another host, and not once it is withdrawn.
	elsewhere := other(t, func(m *solutionhost.ModuleManifest) { m.Alias = "wiki"; m.Host.Coordinate = "obin/prod/eu" })
	require.NoError(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{elsewhere}, valid(t)))
	withdrawn := other(t, func(m *solutionhost.ModuleManifest) {
		m.Alias, m.Removed, m.Workloads, m.Endpoints, m.Authority, m.Frontend = "wiki", true, nil, nil, nil, nil
	})
	require.NoError(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{withdrawn}, valid(t)))

	// A reserved namespace refuses the candidate ...
	for _, alias := range []string{"codefly", "codefly.admin"} {
		candidate := valid(t)
		candidate.Alias = alias
		require.ErrorIs(t, solutionhost.CheckAlias(reserved, nil, candidate), composition.ErrCollision, alias)
	}
	// ... and never an unrelated delivery because an incumbent sits in it.
	incumbent := other(t, func(m *solutionhost.ModuleManifest) { m.Alias = "codefly" })
	require.NoError(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{incumbent}, valid(t)))

	// A withdrawal claims nothing.
	require.NoError(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{holder}, removed(t)))
	// The host's own invalid record accuses the host.
	broken := other(t, func(m *solutionhost.ModuleManifest) { m.Generation = 0 })
	require.ErrorIs(t, solutionhost.CheckAlias(reserved, []*solutionhost.ModuleManifest{broken}, valid(t)), solutionhost.ErrAppliedUnusable)
}
