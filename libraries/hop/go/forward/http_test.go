package forward

import (
	"context"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	core "github.com/codefly-dev/core/workcontext"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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
		Signer: hoptest.Signer("run-proof"), Ready: published(t, hoptest.Signer("run-proof")),
		Upstreams: map[string]*url.URL{target.String(): target},
		Decide: func(_ context.Context, method string, md metadata.MD) (decide.Decision, error) {
			decided = method
			if md.Get(hop.WorkContextKey)[0] != "wc-model" {
				t.Fatalf("the decision did not read the Work Context header: %v", md)
			}
			return decide.Decision{Route: &routing.RouteEndpoint{Address: target.String()}, Module: "model", Identity: hop.Identity{Expires: time.Now().Add(time.Minute).Unix(), Owner: "remi", OwnerKind: "human", Tenant: "acme", Scopes: []string{"modelservice.profiles:read"}}}, nil
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
	}; first(hop.TenantKey) != "acme" || first(hop.OwnerKey) != "remi" || first(hop.WorkContextKey) != "wc-model" || first(hop.ProofKey) == "run-proof" || first(hop.ProofKey) == "" || first(hop.ContextKey) == "" {
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
		h := &HTTP{Signer: hoptest.Signer("p"), Ready: published(t, hoptest.Signer("p")), Upstreams: map[string]*url.URL{target.String(): target},
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

func TestHTTPAndConnectIssueTheBindingObservedByTheListener(t *testing.T) {
	for _, transport := range []string{"http", "connect"} {
		t.Run(transport, func(t *testing.T) {
			const procedure = "/example.v1.Service/Read"
			expected := procedure
			if transport == "http" {
				expected = "POST " + procedure
			}
			a := hoptest.New(t)
			token := a.IssueSingleUse(t, "module")
			decoded, err := core.Decode(token)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := hop.NewVerifier(context.Background(), a.PublishHop("binding-test"), "module", hoptest.Replay())
			if err != nil {
				t.Fatal(err)
			}
			var captured metadata.MD
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = metadata.MD{}
				for key, values := range r.Header {
					captured[strings.ToLower(key)] = values
				}
				if _, err := verifier.Verify(r.Context(), captured, expected); err != nil {
					t.Error(err)
					w.WriteHeader(401)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer backend.Close()
			target, _ := url.Parse(backend.URL)
			face := HTTP{Signer: hoptest.Signer("binding-test"), Ready: published(t, hoptest.Signer("binding-test")), Upstreams: map[string]*url.URL{target.String(): target}, Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
				return decide.Decision{Module: "module", Identity: hop.IdentityOf(decoded.Context()), Route: &routing.RouteEndpoint{Transport: transport, Address: target.String()}}, nil
			}}
			req := httptest.NewRequest(http.MethodPost, procedure, nil)
			req.Header.Set(hop.WorkContextKey, token)
			rec := httptest.NewRecorder()
			face.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("forwarded status %d", rec.Code)
			}
			if _, err := verifier.Verify(context.Background(), captured, expected); err == nil || !strings.Contains(err.Error(), "replay") {
				t.Fatalf("captured replay: %v", err)
			}
			if _, err := verifier.Verify(context.Background(), captured, "/example.v1.Service/Delete"); err == nil || !strings.Contains(err.Error(), "stamp_method") {
				t.Fatalf("retargeted stamp: %v", err)
			}
		})
	}
}

// A Connect caller is refused in Connect's words: its client reads the code
// and the authority's reason, not a status line.
func TestAConnectRefusalKeepsTheAuthoritysReason(t *testing.T) {
	h := &HTTP{Signer: hoptest.Signer("refusal"), Ready: published(t, hoptest.Signer("refusal")), Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
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

// Review #30 F1: only a caller that says it speaks Connect (or gRPC) is
// refused in Connect's words. A REST or form caller, whose body is JSON or a
// form and who sends no Connect-Protocol-Version, keeps {"error": reason} and
// the HTTP status the hop always answered it with.
func TestARESTCallerKeepsItsErrorBodyAndStatus(t *testing.T) {
	for code, want := range map[codes.Code]int{
		codes.Unauthenticated:    http.StatusUnauthorized,
		codes.PermissionDenied:   http.StatusForbidden,
		codes.InvalidArgument:    http.StatusBadRequest,
		codes.NotFound:           http.StatusNotFound,
		codes.Unavailable:        http.StatusServiceUnavailable,
		codes.DeadlineExceeded:   http.StatusServiceUnavailable,
		codes.FailedPrecondition: http.StatusInternalServerError,
	} {
		h := &HTTP{Signer: hoptest.Signer("rest"), Ready: published(t, hoptest.Signer("rest")), Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
			return decide.Decision{}, status.Error(code, "the authority said why")
		}}
		for name, req := range map[string]*http.Request{
			"GET":       httptest.NewRequest(http.MethodGet, "/v1/model/profiles", nil),
			"JSON POST": withType(httptest.NewRequest(http.MethodPost, "/v1/model/invoke", strings.NewReader("{}")), "application/json"),
			"form POST": withType(httptest.NewRequest(http.MethodPost, "/v1/model/invoke", strings.NewReader("a=b")), "application/x-www-form-urlencoded"),
		} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != want || rec.Body.String() != "{\"error\":\"the authority said why\"}\n" {
				t.Errorf("%v, %s: answered %d %s, want %d {\"error\"}", code, name, rec.Code, rec.Body.String(), want)
			}
		}
	}
	// A Connect GET says so with ?connect=v1, and a gRPC caller by its content
	// type: both are still answered in their protocol's words.
	h := &HTTP{Signer: hoptest.Signer("rest"), Ready: published(t, hoptest.Signer("rest")), Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
		return decide.Decision{}, status.Error(codes.PermissionDenied, "the role lacks robin.tools:read")
	}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/robin.chat.v1.ChatService/GetRunnableTools?connect=v1&encoding=json&message=%7B%7D", nil))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"permission_denied"`) {
		t.Fatalf("a Connect GET answered %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, withType(httptest.NewRequest(http.MethodPost, "/robin.chat.v1.ChatService/GetRunnableTools", strings.NewReader("")), "application/grpc"))
	if got := rec.Result().Header.Get("Grpc-Status") + rec.Result().Trailer.Get("Grpc-Status"); got != "7" {
		t.Fatalf("a gRPC caller answered %d grpc-status %q", rec.Code, got)
	}
}

func withType(r *http.Request, contentType string) *http.Request {
	r.Header.Set("Content-Type", contentType)
	return r
}
