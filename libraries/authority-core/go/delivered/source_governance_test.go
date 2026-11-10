package delivered_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/delivered"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
)

// The scopes that govern a module's sources ride on core's signed manifest,
// which every host verifies, so every host reads the same ones; a manifest
// naming none governs no source.
func TestTheGoverningScopesAreReadFromCoresManifest(t *testing.T) {
	manifest := &solutionhost.ModuleManifest{Alias: "notes", Kind: solutionhost.KindSolution, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "notes", ResourceKinds: []string{"notes.page"},
			SourceGovernance: []string{"notes.page:write", "notes.page:publish"}}}
	m, err := delivered.Module(manifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := scope.Normalize([]*basev0.WorkScopeV1{ws("notes.page", "publish", "write")}); !scope.Same(m.SourceGovernance, want) {
		t.Fatalf("governing scopes %v, want %v", m.SourceGovernance, want)
	}
	manifest.Authority.SourceGovernance = nil
	if m := delivered.FromCore(manifest); len(m.SourceGovernance) != 0 {
		t.Fatalf("a manifest naming no governance governs by %v", m.SourceGovernance)
	}
}
