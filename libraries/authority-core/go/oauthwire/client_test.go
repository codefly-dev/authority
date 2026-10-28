package oauthwire_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/oauthwire"
)

func TestPublicClientRedirects(t *testing.T) {
	registered := []string{"http://127.0.0.1/callback", "https://client.invalid/callback?fixed=1"}
	if err := oauthwire.ValidateRegistration("Unverified client", registered); err != nil {
		t.Fatal(err)
	}
	if err := oauthwire.ValidateRegistration("", registered); err != nil {
		t.Fatalf("optional client_name was required: %v", err)
	}
	for _, uri := range []string{registered[0], registered[1], "http://127.0.0.1:49152/callback"} {
		if !oauthwire.AllowsRedirect(registered, uri) {
			t.Fatalf("registered redirect refused: %s", uri)
		}
	}
	for _, uri := range []string{"http://127.0.0.1:49152/other", "http://127.0.0.2/callback", "http://localhost/callback", "http://127.0.0.1/%63allback", "https://client.invalid/callback", "https://client.invalid/callback?fixed=2", "https://client.invalid:443/callback?fixed=1", "https://client.invalid/callback?fixed=1#x", "https://client.invalid/callback?fixed=1&extra=1"} {
		if oauthwire.AllowsRedirect(registered, uri) {
			t.Fatalf("unregistered redirect accepted: %s", uri)
		}
	}
	for _, uri := range []string{"/callback", "javascript:alert(1)", "http://client.invalid/callback", "https://person@client.invalid/callback", "https://*.invalid/callback", "https://client.invalid/callback#", "http://127.0.0.1:0/callback", "https://client.invalid:99999/callback", "https://client.invalid:/callback", "https://client.invalid/callback\r\n"} {
		if err := oauthwire.ValidateRegistration("client", []string{uri}); err == nil {
			t.Fatalf("unsafe registration accepted: %s", uri)
		}
	}
	if err := oauthwire.ValidateRegistration("client", nil); err == nil {
		t.Fatal("no callback accepted")
	}
	if err := oauthwire.ValidateRegistration(strings.Repeat("x", 129), registered); err == nil {
		t.Fatal("unbounded name accepted")
	}
}
