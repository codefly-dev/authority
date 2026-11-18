package main

import (
	"crypto/ed25519"
	"crypto/rand"
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
