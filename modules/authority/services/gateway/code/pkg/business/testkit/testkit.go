// Package testkit composes a mini gateway for tests: the fixture, a launcher
// key, two modules and a solution, as a local run would deliver them.
package testkit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
)

// Kit is a composed mini gateway.
type Kit struct {
	State    *state.State
	Issuer   *issuer.Issuer
	Launcher ed25519.PrivateKey
	Now      time.Time
}

// Scope builds one scope.
func Scope(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

// Documents is a module with one binding towards model.
func Documents(generation uint64) state.Manifest {
	return state.Manifest{Module: "documents", Principal: "documents", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("documents", "read", "write", "ingest"), Scope("documents.collection", "read", "transfer", "admin")},
		Bindings: map[string]state.Binding{"model": {ID: "model", Audience: "model",
			InvokeScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}}},
	}
}

// Model is the module documents calls.
func Model(generation uint64) state.Manifest {
	return state.Manifest{Module: "model", Principal: "model", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read", "admin")}}
}

// Wiki is a solution.
func Wiki(generation uint64) state.Manifest {
	return state.Manifest{Module: "wiki", Principal: "wiki", Kind: "solution", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("wiki.page", "read", "write")}}
}

// FixturePath is the committed fixture.
func FixturePath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "local.yaml")
}

// New composes documents, model and the fixture, then installs the wiki from it.
func New(t *testing.T) *Kit {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	st := state.New(pub)
	for _, m := range []state.Manifest{Model(1), Documents(1), Wiki(1)} {
		if _, err := st.ApplyManifest(m); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(FixturePath())
	if err != nil {
		t.Fatal(err)
	}
	// The fixture must be loaded after the modules are composed, because it
	// installs the wiki and a module installation exists per organisation.
	if err := st.LoadFixture(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	return &Kit{State: st, Launcher: priv, Now: now,
		Issuer: issuer.New(st, "https://authority.local.test", "local-1", signing, func() time.Time { return now })}
}
