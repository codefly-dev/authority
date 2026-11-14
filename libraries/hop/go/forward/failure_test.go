package forward

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// A decision that reached no verdict is refused, and refused as what it is. A
// REST caller whose request ended (a page or view switch cancels it) is
// answered 499, the status a proxy records for a client that closed its
// request, never the 500 that reads as a server fault. A deadline or an
// authority that did not answer stays 503. A denial stays a denial.
func TestARESTCallerWhoseDecisionFailedIsAnsweredWithTheFailure(t *testing.T) {
	reached := false
	module := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	for code, want := range map[codes.Code]int{
		codes.Canceled:         499,
		codes.DeadlineExceeded: http.StatusServiceUnavailable,
		codes.Unavailable:      http.StatusServiceUnavailable,
		codes.PermissionDenied: http.StatusForbidden,
		codes.Unauthenticated:  http.StatusUnauthorized,
	} {
		h := &HTTP{Signer: hoptest.Signer("failure"), Ready: published(t, hoptest.Signer("failure")), Upstreams: map[string]*url.URL{target.String(): target},
			Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
				return decide.Decision{}, status.Error(code, "the authority said why")
			}}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/model/profiles", nil))
		if rec.Code != want || rec.Body.String() != "{\"error\":\"the authority said why\"}\n" {
			t.Errorf("%v answered %d %s, want %d", code, rec.Code, rec.Body.String(), want)
		}
	}
	if reached {
		t.Fatal("a refused request reached the module")
	}
}

// A caller that ended its request while the hop was forwarding it is not a
// module that did not answer: the module may be healthy. Canceled, 499.
func TestACallerThatEndsItsRequestMidForwardIsCanceled(t *testing.T) {
	module := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	h := &HTTP{Signer: hoptest.Signer("ended"), Ready: published(t, hoptest.Signer("ended")), Upstreams: map[string]*url.URL{target.String(): target},
		Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
			return decide.Decision{Route: &routing.RouteEndpoint{Address: target.String()}, Module: "model",
				Identity: hop.Identity{Expires: time.Now().Add(time.Minute).Unix(), Owner: "jane", OwnerKind: "human", Tenant: "acme"}}, nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/model/profiles", nil).WithContext(ctx)
	req.Header.Set(hop.WorkContextKey, "wc-model")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 499 || strings.Contains(rec.Body.String(), "did not answer") {
		t.Fatalf("answered %d %s", rec.Code, rec.Body.String())
	}
}

// A Connect caller keeps the failure's own code.
func TestAConnectCallerWhoseDecisionFailedKeepsItsCode(t *testing.T) {
	h := &HTTP{Signer: hoptest.Signer("connect-failure"), Ready: published(t, hoptest.Signer("connect-failure")), Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
		return decide.Decision{}, status.Error(codes.Canceled, "context canceled")
	}}
	req := httptest.NewRequest(http.MethodPost, "/example.v1.Service/Read", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"code":"canceled"`) {
		t.Fatalf("answered %d %s", rec.Code, rec.Body.String())
	}
}
