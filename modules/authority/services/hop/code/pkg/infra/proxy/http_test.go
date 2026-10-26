package proxy

import (
	"context"
	"hop/pkg/business/decide"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// An HTTP request is decided for "<VERB> <path>" with its headers as the call's
// metadata, and goes on to the module with the hop's stamp and none of the
// caller's.
func TestAnHTTPRequestIsDecidedThenStampedAndForwarded(t *testing.T) {
	var seen *http.Request
	module := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		_, _ = io.WriteString(w, `{"profiles":[]}`)
	}))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	var decided string
	h := &HTTP{
		Proof:     "run-proof",
		Upstreams: map[string]*url.URL{target.String(): target},
		Decide: func(_ context.Context, method string, md metadata.MD) (decide.Decision, error) {
			decided = method
			if md.Get(hop.WorkContextKey)[0] != "wc-model" {
				t.Fatalf("the decision did not read the Work Context header: %v", md)
			}
			return decide.Decision{Route: &routing.RouteEndpoint{Address: target.String()}, Module: "model", Identity: hop.Identity{Owner: "remi", OwnerKind: "human", Tenant: "acme", Scopes: []string{"modelservice.profiles:read"}}}, nil
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/model/profiles?x=1", nil)
	req.Header.Set(hop.WorkContextKey, "wc-model")
	req.Header.Set(hop.TenantKey, "globex") // a caller's stamp, never the hop's
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || decided != "GET /v1/model/profiles" {
		t.Fatalf("answered %d for %q", rec.Code, decided)
	}
	if seen.URL.Path != "/v1/model/profiles" || seen.URL.RawQuery != "x=1" {
		t.Fatalf("forwarded %s", seen.URL)
	}
	md := metadata.MD{}
	for key, values := range seen.Header {
		md[strings.ToLower(key)] = values
	}
	// The stamp as the hop wrote it (the caller's tenant replaced); the module's
	// Verifier authenticates it against the token, proven in libraries/hop/go.
	if first := func(k string) string {
		v := md.Get(k)
		if len(v) != 1 {
			return ""
		}
		return v[0]
	}; first(hop.TenantKey) != "acme" || first(hop.OwnerKey) != "remi" || first(hop.WorkContextKey) != "wc-model" || first(hop.ProofKey) != "run-proof" || first(hop.ContextKey) == "" {
		t.Fatalf("the hop stamped %v", md)
	}
}

// A refusal is answered in HTTP's words with the decision's reason, and nothing
// reaches the module.
func TestAnHTTPRefusalNeverReachesTheModule(t *testing.T) {
	reached := false
	module := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	for code, want := range map[codes.Code]int{
		codes.Unauthenticated:  http.StatusUnauthorized,
		codes.PermissionDenied: http.StatusForbidden,
		codes.Unavailable:      http.StatusServiceUnavailable,
	} {
		h := &HTTP{Proof: "p", Upstreams: map[string]*url.URL{target.String(): target},
			Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
				return decide.Decision{}, status.Error(code, "the authority said why")
			}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/model/invoke", nil))
		if rec.Code != want || !strings.Contains(rec.Body.String(), "the authority said why") {
			t.Fatalf("%v answered %d %s", code, rec.Code, rec.Body.String())
		}
	}
	if reached {
		t.Fatal("a refused request reached the module")
	}
}

// A Connect caller is refused in Connect's words: its client reads the code
// and the authority's reason, not a status line.
func TestAConnectRefusalKeepsTheAuthoritysReason(t *testing.T) {
	h := &HTTP{Proof: "p", Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
		return decide.Decision{}, status.Error(codes.PermissionDenied, "the role lacks robin.tools:read")
	}}
	req := httptest.NewRequest(http.MethodPost, "/robin.chat.v1.ChatService/GetRunnableTools", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"permission_denied"`) || !strings.Contains(rec.Body.String(), "the role lacks robin.tools:read") {
		t.Fatalf("answered %d %s", rec.Code, rec.Body.String())
	}
}
