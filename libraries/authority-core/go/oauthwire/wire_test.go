package oauthwire_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/oauthwire"
)

func discovery(t *testing.T) oauthwire.Discovery {
	t.Helper()
	s := httptest.NewTLSServer(nil)
	t.Cleanup(s.Close)
	return oauthwire.Discovery{
		Resource:            s.URL + "/v1/example/mcp",
		ResourceMetadataURL: s.URL + "/.well-known/oauth-protected-resource/v1/example/mcp",
		Issuer:              s.URL, AuthorizationEndpoint: s.URL + "/authorize", TokenEndpoint: s.URL + "/token",
	}
}

func TestDiscoveryPreservesTheDeclaredResourceAndIssuer(t *testing.T) {
	d := discovery(t)
	r, a, err := d.Documents()
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := d.Challenge()
	if err != nil || challenge != `Bearer resource_metadata="`+d.ResourceMetadataURL+`"` {
		t.Fatalf("challenge %q: %v", challenge, err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var resource map[string]any
	if err := json.Unmarshal(raw, &resource); err != nil {
		t.Fatal(err)
	}
	if resource["resource"] != d.Resource || resource["authorization_servers"].([]any)[0] != d.Issuer || resource["bearer_methods_supported"].([]any)[0] != "header" {
		t.Fatalf("resource metadata: %s", raw)
	}
	raw, err = json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var server map[string]any
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"issuer": d.Issuer, "authorization_endpoint": d.AuthorizationEndpoint, "token_endpoint": d.TokenEndpoint} {
		if server[key] != want {
			t.Fatalf("%s: got %v, want %s", key, server[key], want)
		}
	}
	if server["code_challenge_methods_supported"].([]any)[0] != "S256" || server["token_endpoint_auth_methods_supported"].([]any)[0] != "none" {
		t.Fatalf("public client PKCE metadata: %s", raw)
	}
	for _, field := range []string{"registration_endpoint", "client_id_metadata_document_supported", "scopes_supported"} {
		if _, exists := server[field]; exists {
			t.Fatalf("unconfigured capability %s advertised", field)
		}
	}
	// No guessed route layout, case folding, path cleaning or trailing slash
	// removal: these are different resource identifiers under RFC 8707.
	for _, path := range []string{"/proxy/example/mcp/", "/v1/%65xample/mcp", "/v1/EXAMPLE/mcp"} {
		d.Resource = d.Issuer + path
		r, _, err := d.Documents()
		if err != nil || r.Resource != d.Resource {
			t.Fatalf("declared resource changed: %+v %v", r, err)
		}
	}
}

func TestDiscoveryRefusesIncompleteOrUnsafeDeclarations(t *testing.T) {
	base := discovery(t)
	for name, change := range map[string]func(*oauthwire.Discovery){
		"missing resource":  func(d *oauthwire.Discovery) { d.Resource = "" },
		"missing issuer":    func(d *oauthwire.Discovery) { d.Issuer = "" },
		"missing authorize": func(d *oauthwire.Discovery) { d.AuthorizationEndpoint = "" },
		"missing token":     func(d *oauthwire.Discovery) { d.TokenEndpoint = "" },
		"relative metadata": func(d *oauthwire.Discovery) { d.ResourceMetadataURL = "/metadata" },
		"other origin metadata": func(d *oauthwire.Discovery) {
			d.ResourceMetadataURL = strings.Replace(d.ResourceMetadataURL, "https:", "http:", 1)
			d.Local = true
		},
		"query":                       func(d *oauthwire.Discovery) { d.Resource += "?token=secret" },
		"empty query":                 func(d *oauthwire.Discovery) { d.Resource += "?" },
		"fragment":                    func(d *oauthwire.Discovery) { d.Issuer += "#" },
		"userinfo":                    func(d *oauthwire.Discovery) { d.Issuer = strings.Replace(d.Issuer, "://", "://person@", 1) },
		"header injection":            func(d *oauthwire.Discovery) { d.ResourceMetadataURL += "\"\r\nX: injected" },
		"padding":                     func(d *oauthwire.Discovery) { d.Resource += " " },
		"remote http":                 func(d *oauthwire.Discovery) { d.Issuer = "http://issuer.invalid"; d.Local = true },
		"invalid registration":        func(d *oauthwire.Discovery) { d.RegistrationEndpoint = "/register" },
		"scope list instead of token": func(d *oauthwire.Discovery) { d.Scopes = []string{"read write"} },
	} {
		t.Run(name, func(t *testing.T) {
			d := base
			change(&d)
			if _, _, err := d.Documents(); err == nil {
				t.Fatal("invalid discovery accepted")
			}
			if challenge, err := d.Challenge(); err == nil || challenge != "" {
				t.Fatalf("invalid discovery advertised: %q %v", challenge, err)
			}
		})
	}
	base.Issuer = strings.Replace(base.Issuer, "https:", "http:", 1)
	if _, _, err := base.Documents(); err == nil {
		t.Fatal("HTTP allowed without local composition")
	}
	base.Local = true
	if _, _, err := base.Documents(); err != nil {
		t.Fatal(err)
	}
}

func TestPKCERFC7636VectorAndRefusals(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if err := oauthwire.VerifyPKCE("S256", challenge, verifier); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"", "plain", "s256"} {
		if err := oauthwire.VerifyPKCE(method, challenge, verifier); err == nil {
			t.Fatalf("method %q accepted", method)
		}
	}
	for _, bad := range []string{"", challenge + "=", challenge[:42], challenge + "A", strings.Repeat("~", 43), challenge[:42] + "N"} {
		if err := oauthwire.ValidateChallenge("S256", bad); err == nil {
			t.Fatalf("malformed or noncanonical challenge %q accepted", bad)
		}
	}
	for _, bad := range []string{"", verifier[:42], strings.Repeat("a", 129), verifier + " ", verifier + "+", strings.Repeat("a", 43)} {
		if err := oauthwire.VerifyPKCE("S256", challenge, bad); err == nil {
			t.Fatalf("wrong verifier %q accepted", bad)
		}
	}
	for _, n := range []int{43, 128} {
		v := strings.Repeat("~", n)
		h := sha256.Sum256([]byte(v))
		if err := oauthwire.VerifyPKCE("S256", base64.RawURLEncoding.EncodeToString(h[:]), v); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResourceBindingNeverWidens(t *testing.T) {
	d := discovery(t)
	if err := oauthwire.CheckResource(d.Resource, d.Resource); err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"", d.Issuer + "/v1/another/mcp", d.Issuer, d.Resource + "/", d.Resource + "?x=1", strings.ToUpper(d.Resource), strings.Replace(d.Resource, "example", "%65xample", 1)} {
		if err := oauthwire.CheckResource(d.Resource, other); err == nil {
			t.Fatalf("different resource %q admitted", other)
		}
	}
	if err := oauthwire.CheckResource("", ""); err == nil {
		t.Fatal("unbound credential admitted")
	}
}

func TestLifetimeIsTheEarlierEndRoundedDown(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		capability, delegation time.Duration
		want                   int64
	}{
		{15 * time.Minute, 24 * time.Hour, 900},
		{15 * time.Minute, 30 * time.Second, 30},
		{1500 * time.Millisecond, time.Hour, 1},
		{time.Hour, 999 * time.Millisecond, 0},
		{0, time.Hour, 0}, {time.Hour, 0, 0}, {time.Hour, -time.Second, 0},
	} {
		got, err := oauthwire.ExpiresIn(now, now.Add(tc.capability), now.Add(tc.delegation))
		if got != tc.want || (err != nil) != (tc.want == 0) {
			t.Fatalf("%+v: got %d, %v", tc, got, err)
		}
	}
	if _, err := oauthwire.ExpiresIn(now, now.Add(time.Hour), time.Time{}); err == nil {
		t.Fatal("unbounded delegation accepted")
	}
	if _, err := oauthwire.ExpiresIn(now, time.Time{}, now.Add(time.Hour)); err == nil {
		t.Fatal("missing capability accepted")
	}
}
