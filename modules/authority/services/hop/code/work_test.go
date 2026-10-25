package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/codefly-dev/core/resources"
	"hop/pkg/adapters"
)

// Startup reads the same SDK carriers as a composed process. grpc.NewClient
// is lazy: these refusals neither contact an authority nor start a proxy.
func TestHopStartupRequiresGeneratedRoutes(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, resources.LocalEnvironment().Name)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv(resources.WorkspaceSecretConfigurationPrefix+"__HOP__PROOF", "controlled-test-proof")
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__AUTHORITY__ENDPOINT", listener.Addr().String())
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP__MODULES", "example")
	// Legacy values must not make an absent or invalid generated view acceptable.
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP__UPSTREAM_EXAMPLE", listener.Addr().String())
	for _, tc := range []struct{ name, raw, want string }{
		{"empty", "", "generated hop-routes/ROUTES is required"},
		{"malformed", "{", "hop routes:"},
		{"unknown-schema", `{"schema":"other","endpoints":[]}`, "hop routes:"},
		{"empty-inventory", `{"schema":"codefly.dev/hop-routes/v1","endpoints":[]}`, "hop routes:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP-ROUTES__ROUTES", tc.raw)
			t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP_ROUTES__ROUTES", tc.raw)
			cleanup, err := standInFront(context.Background(), &adapters.Configuration{})
			if cleanup != nil {
				cleanup()
				t.Fatal("invalid routing started the hop")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}
}
