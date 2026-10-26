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
	t.Setenv(resources.ModulePrefix, "authority")
	t.Setenv(resources.ServicePrefix, "hop")
	t.Setenv(resources.EnvironmentPrefix, resources.LocalEnvironment().Name)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv(resources.ServiceSecretConfigurationPrefix+"__AUTHORITY__HOP__HOP_SIGNING__SEED", strings.Repeat("01", 32))
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__AUTHORITY__ENDPOINT", listener.Addr().String())
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP__MODULES", "example")
	// Legacy values must not make an absent or invalid generated view acceptable.
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP__UPSTREAM_EXAMPLE", listener.Addr().String())
	for _, tc := range []struct{ name, raw, want string }{
		{"empty", "", RouteProducerVersion},
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

func TestHopStartupRefusesUnprotectedUpstreamTransport(t *testing.T) {
	t.Setenv(resources.ModulePrefix, "authority")
	t.Setenv(resources.ServicePrefix, "hop")
	t.Setenv(resources.EnvironmentPrefix, resources.LocalEnvironment().Name)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv(resources.ServiceSecretConfigurationPrefix+"__AUTHORITY__HOP__HOP_SIGNING__SEED", strings.Repeat("01", 32))
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__AUTHORITY__ENDPOINT", listener.Addr().String())
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP__MODULES", "example")
	for _, transport := range []string{"grpc", "http", "connect"} {
		t.Run(transport, func(t *testing.T) {
			method := "/example.Service/Call"
			if transport == "http" {
				method = "GET /items"
			}
			raw := `{"schema":"codefly.dev/hop-routes/v1","endpoints":[{"audience":"example","service":"api","endpoint":"api","transport":"` + transport + `","address":"http://unprotected.example:8080","package":"owner/example","version":"1","digest":"sha256:test","methods":["` + method + `"]}]}`
			t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP-ROUTES__ROUTES", raw)
			t.Setenv(resources.WorkspaceConfigurationPrefix+"__HOP_ROUTES__ROUTES", raw)
			cleanup, err := standInFront(context.Background(), &adapters.Configuration{})
			if cleanup != nil {
				cleanup()
				t.Fatal("unprotected upstream started")
			}
			if err == nil || !strings.Contains(err.Error(), "requires HTTPS") {
				t.Fatalf("transport refusal: %v", err)
			}
		})
	}
}
