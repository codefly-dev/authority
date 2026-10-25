package host

import (
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
