package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/codefly-dev/core/resources"
)

// The local authority answers an advisory check as advice only in the run
// named exactly "local": the environment the composition started it in, the
// one signal it reads. Any other run, or none stated, enforces every check.
func TestAdviceIsServedOnlyInTheRunNamedLocal(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for environment, want := range map[string]bool{"local": true, "": false, "Local": false, "staging": false, "local-preview": false} {
		t.Setenv(resources.EnvironmentPrefix, environment)
		if got := localRun(); got != want {
			t.Errorf("%s=%q: local run %v, want %v", resources.EnvironmentPrefix, environment, got, want)
		}
		if got := coreConfig("k", key).Advisory; got != want {
			t.Errorf("%s=%q: the core serves advice %v, want %v", resources.EnvironmentPrefix, environment, got, want)
		}
	}
}

// The local authority serves a fixture and nothing else, so it starts only on
// a fixture the run selected by name, in the run named exactly "local".
// Nothing is defaulted: an environment that selected no fixture (it loads a
// real provider) gets no fixture people, and a fixture selected anywhere but
// a developer's own run is refused.
func TestTheFixtureIsServedOnlyWhenSelectedInALocalRun(t *testing.T) {
	for name, tc := range map[string]struct {
		environment, fixture, want, refusal string
	}{
		"selected in a local run":      {"local", "local", "local", ""},
		"no fixture selected":          {"local", "", "", "selected no fixture"},
		"selected outside a local run": {"staging", "local", "", `"staging"`},
		"no run named":                 {"", "local", "", "names no environment"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(resources.EnvironmentPrefix, tc.environment)
			t.Setenv(resources.FixturePrefix, tc.fixture)
			got, err := selectedFixture()
			if tc.refusal == "" {
				if err != nil || got != tc.want {
					t.Fatalf("fixture %q, %v; want %q", got, err, tc.want)
				}
				return
			}
			if err == nil || got != "" || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("fixture %q, error %v; want a refusal naming %s", got, err, tc.refusal)
			}
		})
	}
}
