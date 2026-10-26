package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"

	"github.com/codefly-dev/core/configurations"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
)

// Exercise the production boot hook through Codefly's file loader and SDK
// document carrier, rather than passing fixture bytes straight to state.
func TestCompositionReachesBootThroughCodefly(t *testing.T) {
	ctx := context.Background()
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Cleanup(func() { _ = codefly.InjectConfigurations() })
	for _, tc := range []struct {
		name, document, path, reason string
		granted                      bool
	}{
		{name: "absent", reason: "no fixture-composition document was delivered"},
		{name: "shipped default", path: testkit.DefaultCompositionPath()},
		{name: "composition", document: "schema: codefly.dev/authority/fixture-composition/v1\nroles:\n  - organization: acme\n    name: editor\n    scopes:\n      - {kind: ledger.entry, actions: [write]}\n", granted: true},
		{name: "unknown role", document: "schema: codefly.dev/authority/fixture-composition/v1\nroles: [{organization: acme, name: missing, scopes: [{kind: ledger.entry, actions: [write]}]}]", reason: "acme/missing is not a role"},
		{name: "null", document: "null", reason: "not a mapping"},
		{name: "unversioned", document: "{}", reason: "schema is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := codefly.InjectConfigurations(); err != nil {
				t.Fatal(err)
			}
			if tc.path != "" {
				data, err := os.ReadFile(tc.path)
				if err != nil {
					t.Fatal(err)
				}
				tc.document = string(data)
			}
			if tc.document != "" {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "fixture-composition.yaml"), []byte(tc.document), 0600); err != nil {
					t.Fatal(err)
				}
				infos, err := configurations.LoadConfigurationInformationsFromFiles(ctx, dir)
				if err != nil {
					t.Fatal(err)
				}
				if err := codefly.InjectConfigurations(&basev0.Configuration{Origin: resources.ConfigurationWorkspace, Infos: infos}); err != nil {
					t.Fatal(err)
				}
			}
			k := testkit.New(t)
			ledger := state.Manifest{Name: "ledger", Principal: "ledger", Kind: "module", Generation: 1, ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("ledger.entry", "write")}}
			if _, err := k.State.ApplyManifest(ledger); err != nil {
				t.Fatal(err)
			}
			err := applyComposition(ctx, k.State)
			if tc.reason != "" {
				if err == nil || !strings.Contains(err.Error(), tc.reason) {
					t.Fatalf("got %v, want %s", err, tc.reason)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, scope := range k.State.RoleScopes("acme", "editor") {
				if scope.GetResourceKind() == "ledger.entry" {
					found = true
				}
			}
			if found != tc.granted {
				t.Fatalf("composition grant present = %v, want %v", found, tc.granted)
			}
		})
	}
}
