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
	"github.com/codefly-dev/core/workloadidentity"
	"github.com/codefly-dev/core/workloadidentity/native"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
)

// Kit is a composed mini gateway.
type Kit struct {
	State    *state.State
	Issuer   *issuer.Issuer
	Launcher *native.Issuer // the run's launcher, as the CLI is one
	Now      time.Time
}

// Audience is the name the launcher issues credentials to: this host.
const Audience = "https://authority.local.test"

// Workload is the process the launcher started for a module, as it declares it.
func Workload(module string) workloadidentity.Workload {
	return workloadidentity.Workload{TrustDomain: "local.test", Module: module, Service: module, Instance: module + "-1"}
}

// Credential is what the launcher signed for one module's process.
func (k *Kit) Credential(t *testing.T, module string) string {
	t.Helper()
	token, err := k.Launcher.Issue(native.Subject{Workload: Workload(module), Container: module}, Audience)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Scope builds one scope.
func Scope(kind string, actions ...string) *basev0.WorkScopeV1 {
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: actions}
}

// Documents is a module with one binding towards model.
func Documents(generation uint64) state.Manifest {
	return state.Manifest{Module: "documents", Principal: "documents", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("documents", "read", "write", "ingest"), Scope("documents.collection", "read", "transfer", "admin")},
		Bindings: map[string]state.Binding{
			"model": {ID: "model", Audience: "model",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read")}},
			"runtime-admission": {ID: "runtime-admission", Audience: "runtime",
				InvokeScopes: []*basev0.WorkScopeV1{Scope("runtime.task", "admit", "read")}, HeadlessScopes: []*basev0.WorkScopeV1{Scope("runtime.task", "read")}},
		},
	}
}

// Model is the module documents calls.
func Model(generation uint64) state.Manifest {
	return state.Manifest{Module: "model", Principal: "model", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("modelservice.profiles", "invoke", "read", "admin")}}
}

// Runtime is the module documents fans work out through.
func Runtime(generation uint64) state.Manifest {
	return state.Manifest{Module: "runtime", Principal: "runtime", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("runtime.task", "admit", "read")}}
}

// Records is the module the directory page reads.
func Records(generation uint64) state.Manifest {
	return state.Manifest{Module: "records", Principal: "records", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("records.record", "read", "write"), Scope("records.type", "read")}}
}

// OrgDirectory is a module with a page and no bindings; it reads records for the viewer.
func OrgDirectory(generation uint64) state.Manifest {
	return state.Manifest{Module: "org-directory", Principal: "org-directory", Kind: "module", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("directory.entry", "read", "write")}}
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
	launcher, err := native.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	// The launcher declares the processes it starts, one per module; its anchor
	// vouches for exactly those.
	for _, module := range []string{"model", "runtime", "records", "org-directory", "documents", "wiki"} {
		launcher.Declare(Workload(module))
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	st, err := state.New(launcher.Anchor(), Audience)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []state.Manifest{Model(1), Runtime(1), Records(1), OrgDirectory(1), Documents(1), Wiki(1)} {
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
	return &Kit{State: st, Launcher: launcher, Now: now,
		Issuer: issuer.New(st, Audience, "local-1", signing, func() time.Time { return now })}
}
