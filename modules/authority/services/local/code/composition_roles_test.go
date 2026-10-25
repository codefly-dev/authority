package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gateway/pkg/business/testkit"

	"github.com/codefly-dev/core/configurations"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
)

// Exercise the production boot hook through Codefly's file loader and SDK
// document carrier, rather than passing fixture bytes straight to state.
func TestCompositionRolesReachBootThroughCodefly(t *testing.T) {
	ctx := context.Background()
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Cleanup(func() { _ = codefly.InjectConfigurations() })
	for _, tc := range []struct {
		name, document, reason string
		granted                bool
	}{
		{name: "absent"},
		{name: "composition", document: "roles:\n  - organization: acme\n    name: editor\n    scopes:\n      - {kind: ledger.entry, actions: [write]}\n", granted: true},
		{name: "unknown role", document: "roles: [{organization: acme, name: missing, scopes: [{kind: ledger.entry, actions: [write]}]}]", reason: "acme/missing is not a role"},
		{name: "null", document: "null", reason: "empty or null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := codefly.InjectConfigurations(); err != nil {
				t.Fatal(err)
			}
			if tc.document != "" {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "fixture-roles.yaml"), []byte(tc.document), 0600); err != nil {
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
			err := grantCompositionRoles(ctx, k.State)
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
