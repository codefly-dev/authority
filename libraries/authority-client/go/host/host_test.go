package host

import (
	"context"
	"errors"
	"github.com/codefly-dev/core/resources"
	"strings"
	"testing"
)

// The host is where authority/endpoint says, over the transport its scheme
// names; with none, the composed local authority's address.
func TestHostTargetReadsTheConfiguredEndpoint(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, resources.LocalEnvironment().Name)
	local := func() (string, error) { return "localhost:7000", nil }
	for _, tc := range []struct {
		endpoint, target, protocol string
	}{
		{"", "localhost:7000", "insecure"},
		{"  ", "localhost:7000", "insecure"},
		{"localhost:9000", "localhost:9000", "insecure"},
		{"http://localhost:8080", "localhost:8080", "insecure"},
		{"http://localhost", "localhost:80", "insecure"},
		{"grpc://localhost:9000", "localhost:9000", "insecure"},
		{"https://accounts.example.test", "accounts.example.test:443", "tls"},
		{"https://accounts.example.test:8443/", "accounts.example.test:8443", "tls"},
	} {
		target, transport, err := Target(tc.endpoint, local)
		if err != nil || target != tc.target || transport.Info().SecurityProtocol != tc.protocol {
			t.Errorf("%q: target=%q protocol=%v err=%v; want %q over %s", tc.endpoint, target, transport, err, tc.target, tc.protocol)
		}
	}
}

func TestHostTargetRefusesWhatIsNotAnOrigin(t *testing.T) {
	local := func() (string, error) { t.Fatal("a configured endpoint never falls back"); return "", nil }
	for _, endpoint := range []string{"accounts", "ftp://accounts:21", "https://accounts/v1", "https://u:p@accounts", "http://accounts:1?x=1", "http://"} {
		if target, _, err := Target(endpoint, local); err == nil {
			t.Errorf("%q was accepted as %q", endpoint, target)
		}
	}
	if _, _, err := Target("", func() (string, error) { return "", errors.New("not resolved") }); err == nil {
		t.Error("an unresolved local with no endpoint was accepted")
	}
}

func TestNonLocalPlaintextIsRefused(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, resources.LocalEnvironment().Name)
	for _, target := range []string{"remote.test:8080", "http://remote.test", "grpc://10.0.0.2:443", "tcp://[2001:db8::1]:8080"} {
		if _, _, err := Target(target, nil); err == nil {
			t.Fatalf("accepted plaintext %s", target)
		}
	}
	if _, _, err := Target("", func() (string, error) { return "remote.test:8080", nil }); err == nil {
		t.Fatal("fallback bypassed TLS")
	}
	for _, target := range []string{"http://127.0.0.1", "http://[::1]"} {
		if _, _, err := Target(target, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMeshProtectedHostUsesCompositionTransport(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "production")
	for _, assertion := range []string{"", "false", "true", "TRUE", " true", "true "} {
		t.Run("assertion="+assertion, func(t *testing.T) {
			t.Setenv(resources.WorkspaceConfigurationPrefix+"__INTERNAL_TRANSPORT__MESH_PROTECTED", assertion)
			for _, name := range []string{"accounts.platform.svc", "accounts.platform.svc.cluster.local", "accounts.platform.svc.cluster.local.", "10.0.0.2", "remote.test", "localhost", "accounts.platform.svc.evil.test", "accounts..svc", "-accounts.platform.svc", "accounts.plat_form.svc"} {
				validName := name == "accounts.platform.svc" || name == "accounts.platform.svc.cluster.local" || name == "accounts.platform.svc.cluster.local."
				for _, endpoint := range []string{"http://" + name + ":8080", ""} {
					target, transport, err := Target(endpoint, func() (string, error) { return name + ":8080", nil })
					allowed := assertion == "true" && validName
					if (err == nil) != allowed {
						t.Fatalf("assertion %q host %s fallback %v: %v", assertion, name, endpoint == "", err)
					}
					if allowed && (target != name+":8080" || transport.Info().SecurityProtocol != "insecure") {
						t.Fatalf("unexpected mesh transport %s %v", target, transport)
					}
				}
			}
		})
	}
}

func TestMeshAssertionReadFailureAndMisspellingRefuse(t *testing.T) {
	_, err := meshProtected(func(string, string) (string, bool, error) { return "true", true, errors.New("sensitive-value") })
	if err == nil || strings.Contains(err.Error(), "sensitive-value") {
		t.Fatalf("unreadable assertion: %v", err)
	}
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__INTERNAL_TRANSPORT__MESH_PROTECTED", "TRUE")
	if _, _, err := Target("https://accounts.example.test", nil); err == nil {
		t.Fatal("TLS hid invalid mesh assertion")
	}
}

func TestUpstreamEndpointUsesTheSharedTransportGate(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, resources.LocalEnvironment().Name)
	for _, address := range []string{"http://arbitrary.example:8080", "grpc://192.0.2.1:8080", "", "http://localhost:8080/rewritten"} {
		if _, _, err := Endpoint(context.Background(), address); err == nil {
			t.Fatalf("accepted upstream %q", address)
		}
	}
	for _, address := range []string{"http://127.0.0.1:8080", "https://upstream.example"} {
		if _, _, err := Endpoint(context.Background(), address); err != nil {
			t.Fatal(err)
		}
	}
}

// A credential pasted into authority/endpoint never reaches an error: a
// refusal names the host and port alone.
func TestARefusalNeverEchoesTheEndpointValue(t *testing.T) {
	const secret = "s3cr3t-token"
	for _, endpoint := range []string{
		"https://user:" + secret + "@authority.example:8443",
		"https://authority.example:8443/?token=" + secret,
		"https://authority.example:8443/" + secret,
		"https://authority.example:8443/#" + secret,
		"ftp://authority.example:21?k=" + secret,
		"ftp://" + secret + "@authority.example:21",
		secret + "-not-an-address",
		"https://[" + secret,
	} {
		_, _, err := Target(endpoint, nil)
		if err == nil {
			t.Fatalf("%q accepted", endpoint)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal echoes the endpoint's credential: %v", err)
		}
	}
	if _, _, err := Target("https://user:"+secret+"@authority.example:8443", nil); err == nil || !strings.Contains(err.Error(), "authority.example:8443") {
		t.Fatalf("the refusal names the host and port: %v", err)
	}
}

// Loopback is local-kind, as Core's environment model reports it: a playground's
// local-authority run reaches its own authority over loopback; a hosted
// environment never does.
func TestLoopbackIsAdmittedInEveryLocalKindEnvironmentOnly(t *testing.T) {
	for environment, admitted := range map[string]bool{"local": true, "local-authority": true, "local-k3d": true, "staging": false, "obin-staging": false, "production": false, "": false} {
		t.Setenv(resources.EnvironmentPrefix, environment)
		if Local() != admitted {
			t.Errorf("%q: Local() = %v", environment, !admitted)
		}
		for _, endpoint := range []string{"localhost:7000", "http://127.0.0.1:7000", "grpc://[::1]:7000"} {
			if _, _, err := Target(endpoint, nil); (err == nil) != admitted {
				t.Errorf("%q in %q: admitted=%v, want %v (%v)", endpoint, environment, err == nil, admitted, err)
			}
		}
	}
}

// Review r61 m1, held identical in Python (tests/test_host.py): control
// characters, a zone id on a loopback address and an explicit port 0 are refused.
func TestControlCharactersZoneIDsAndPortZeroAreRefused(t *testing.T) {
	t.Setenv(resources.EnvironmentPrefix, "local")
	for _, endpoint := range []string{"http://127.0.0.1\t:80", "http://local\nhost:80", "127.0.0.1\t:80", "localhost:80\x7f", "http://[::1%25lo0]:80", "[::1%lo0]:80", "http://127.0.0.1:0", "127.0.0.1:0", "localhost:00", "https://accounts.example.test:0"} {
		if target, _, err := Target(endpoint, nil); err == nil {
			t.Errorf("%q was admitted as %q", endpoint, target)
		}
	}
}
