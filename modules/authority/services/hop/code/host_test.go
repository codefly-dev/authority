package main

import (
	"errors"
	"testing"
)

// The host is where authority/endpoint says, over the transport its scheme
// names; with none, the composed mini gateway's address.
func TestHostTargetReadsTheConfiguredEndpoint(t *testing.T) {
	gateway := func() (string, error) { return "localhost:7000", nil }
	for _, tc := range []struct {
		endpoint, target, protocol string
	}{
		{"", "localhost:7000", "insecure"},
		{"  ", "localhost:7000", "insecure"},
		{"localhost:9000", "localhost:9000", "insecure"},
		{"http://accounts.saas:8080", "accounts.saas:8080", "insecure"},
		{"http://accounts.saas", "accounts.saas:80", "insecure"},
		{"grpc://localhost:9000", "localhost:9000", "insecure"},
		{"https://accounts.example.test", "accounts.example.test:443", "tls"},
		{"https://accounts.example.test:8443/", "accounts.example.test:8443", "tls"},
	} {
		target, transport, err := hostTarget(tc.endpoint, gateway)
		if err != nil || target != tc.target || transport.Info().SecurityProtocol != tc.protocol {
			t.Errorf("%q: target=%q protocol=%v err=%v; want %q over %s", tc.endpoint, target, transport, err, tc.target, tc.protocol)
		}
	}
}

func TestHostTargetRefusesWhatIsNotAnOrigin(t *testing.T) {
	gateway := func() (string, error) { t.Fatal("a configured endpoint never falls back"); return "", nil }
	for _, endpoint := range []string{"accounts", "ftp://accounts:21", "https://accounts/v1", "https://u:p@accounts", "http://accounts:1?x=1", "http://"} {
		if target, _, err := hostTarget(endpoint, gateway); err == nil {
			t.Errorf("%q was accepted as %q", endpoint, target)
		}
	}
	if _, _, err := hostTarget("", func() (string, error) { return "", errors.New("not resolved") }); err == nil {
		t.Error("an unresolved gateway with no endpoint was accepted")
	}
}
