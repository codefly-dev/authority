package forward

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc/metadata"
)

// The HTTP face forwards no credential of the caller's either: not the
// session cookie, not a bearer, not a proxy credential. The operation's own
// names still arrive.
func TestTheHTTPFaceForwardsNoCallerCredentialToTheModule(t *testing.T) {
	var seen http.Header
	module := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		_, _ = io.WriteString(w, `{}`)
	}))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	h := &HTTP{
		Signer: hoptest.Signer("run-proof"), Ready: published(t, hoptest.Signer("run-proof")),
		Upstreams: map[string]*url.URL{target.String(): target},
		Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
			return decide.Decision{Route: &routing.RouteEndpoint{Address: target.String()}, Module: "model", Identity: hop.Identity{Expires: time.Now().Add(time.Minute).Unix(), Owner: "remi", OwnerKind: "human", Tenant: "acme"}}, nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/model/invoke", nil)
	req.Header.Set(hop.WorkContextKey, "wc-model")
	req.Header.Set("Authorization", "Bearer the-callers-session")
	req.Header.Set("Cookie", "session=the-callers-session")
	req.Header.Set("Proxy-Authorization", "Basic Zm9vOmJhcg==")
	req.Header.Set("Idempotency-Key", "op-1")
	req.Header.Set("X-Codefly-Effect-Id", "effect-1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("answered %d: %s", rec.Code, rec.Body)
	}
	for _, credential := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if got := seen.Values(credential); len(got) != 0 {
			t.Errorf("the module received the caller's %s: %v", credential, got)
		}
	}
	for key, want := range map[string]string{hop.WorkContextKey: "wc-model", "Idempotency-Key": "op-1", "X-Codefly-Effect-Id": "effect-1"} {
		if got := seen.Get(key); got != want {
			t.Errorf("the module received %s %q, want %q", key, got, want)
		}
	}
}
