package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/wool"
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

// logged keeps what a wool logger is told.
type logged struct{ lines []*wool.Log }

func (l *logged) Process(line *wool.Log) { l.lines = append(l.lines, line) }

// forwarded is a hop line as the run shows it: the run forwards the hop's
// output through its own logger, which redacts any line whose label (the
// text before its first "=" or ":") reads as a credential's.
func forwarded(t *testing.T, line *wool.Log) string {
	t.Helper()
	run := &logged{}
	wool.Get(context.Background()).WithLogger(run).Info(line.String())
	if len(run.lines) != 1 {
		t.Fatalf("the run logged %d lines", len(run.lines))
	}
	return run.lines[0].Message
}

// Review #28 F4: the registration log names the published key by its id, and
// a refusal by its reason, and both survive the run's redaction; they never
// name the seed. "the authority publishes this hop's admission key
// admission=hop-…" reached the run as "admission=****".
func TestTheRegistrationLogNamesTheKeyIDThroughTheRunsRedaction(t *testing.T) {
	hop := &logged{}
	report := registrationReport(wool.Get(context.Background()).In("hop").WithLogger(hop))
	seed := strings.Repeat("ab", 32)
	signer, err := stamp.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	id, public := signer.Admission()
	lapses := time.Date(2026, 10, 26, 19, 30, 0, 0, time.UTC)
	report(&authorityv1.PublicKey{KeyId: id, PublicKey: public}, lapses, nil)
	report(nil, time.Time{}, errors.New("rpc error: code = PermissionDenied desc = the registration proof is stale"))
	if len(hop.lines) != 2 {
		t.Fatalf("the hop logged %d lines", len(hop.lines))
	}
	published := forwarded(t, hop.lines[0])
	if !strings.Contains(published, id) || !strings.Contains(published, "2026-10-26T19:30:00Z") || strings.Contains(published, "****") {
		t.Fatalf("the run shows %q, not the key id %s and its lapse", published, id)
	}
	refused := forwarded(t, hop.lines[1])
	if !strings.Contains(refused, "the registration proof is stale") || strings.Contains(refused, "****") {
		t.Fatalf("the run shows %q, not the refusal's reason", refused)
	}
	for _, line := range hop.lines {
		if strings.Contains(line.String(), seed) || strings.Contains(line.String(), signer.PublicKey()) {
			t.Fatalf("the hop logged key material: %s", line.String())
		}
	}
}
