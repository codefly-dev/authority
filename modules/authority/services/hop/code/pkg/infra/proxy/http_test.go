package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go"
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
		Upstreams: map[string]*url.URL{"model": target},
		Decide: func(_ context.Context, method string, md metadata.MD) (string, hop.Identity, error) {
			decided = method
			if md.Get(hop.WorkContextKey)[0] != "wc-model" {
				t.Fatalf("the decision did not read the Work Context header: %v", md)
			}
			return "model", hop.Identity{Owner: "remi", OwnerKind: "human", Tenant: "acme", Scopes: []string{"modelservice.profiles:read"}}, nil
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
	id, err := hop.Read(md, "run-proof")
	if err != nil || id.Tenant != "acme" || id.Owner != "remi" || id.Context != "wc-model" {
		t.Fatalf("the module read %+v, %v", id, err)
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
		h := &HTTP{Proof: "p", Upstreams: map[string]*url.URL{"model": target},
			Decide: func(context.Context, string, metadata.MD) (string, hop.Identity, error) {
				return "", hop.Identity{}, status.Error(code, "the authority said why")
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
