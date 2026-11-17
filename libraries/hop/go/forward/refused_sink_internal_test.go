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
)

// The hop's own refusals never reach the authority: a check the authority did
// not answer inside the hop's deadline, an admission the hop cannot sign, a
// hop with no published admission key. Each reaches the host's sink with its
// reason and what identifies the call, and the log is told what it was told
// before.
func TestAFaceTellsItsSinkTheRefusalsTheAuthorityNeverSees(t *testing.T) {
	module := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	token := hoptest.New(t).Issue(t, "model")
	routes := &routing.Routing{Endpoints: []routing.RouteEndpoint{{Audience: "model", Transport: "http", Address: target.String(), Methods: []string{"GET /v1/model/profiles"}}}}
	var told []Refusal
	var logged []string
	face := func(ready func() bool, decision Decide) *HTTP {
		told, logged = nil, nil
		return &HTTP{Signer: hoptest.Signer("sink"), Ready: ready, Upstreams: map[string]*url.URL{target.String(): target}, Decide: decision,
			Refused: func(method string, err error) { logged = append(logged, method+": "+err.Error()) },
			Sink:    func(_ context.Context, r Refusal) { told = append(told, r) }}
	}
	call := func(h *HTTP) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/model/profiles", nil)
		req.Header.Set(hop.WorkContextKey, token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	one := func(t *testing.T, code codes.Code, reason string) Refusal {
		t.Helper()
		if len(told) != 1 || told[0].Code != code || !strings.Contains(told[0].Reason, reason) || told[0].Method != "GET /v1/model/profiles" || told[0].ByAuthority {
			t.Fatalf("the sink was told %+v, want one %v refusal of the hop's own naming %q", told, code, reason)
		}
		return told[0]
	}
	ready := published(t, hoptest.Signer("sink"))

	t.Run("a stalled check failed closed at the hop's deadline", func(t *testing.T) {
		authority := &stalling{}
		authority.stalled.Store(true)
		h := face(ready, decide.Decider{Authority: authority, Timeout: 100 * time.Millisecond, Modules: map[string]bool{"model": true}, Routes: routes}.Decide)
		if got := call(h); got != http.StatusServiceUnavailable {
			t.Fatalf("a stalled authority was answered %d", got)
		}
		// The authority never verified the Work Context: what it names is claimed.
		got := one(t, codes.Unavailable, "could not reach the authority")
		if got.Module != "model" || got.Owner != "principal-owner" || got.Organization != "tenant-conformance" || got.Actor != "principal-owner" || got.Task == "" || !got.Claimed {
			t.Fatalf("the refusal does not identify the call: %+v", got)
		}
		if len(logged) != 1 {
			t.Fatalf("the log was told %q, want the one line it was always told", logged)
		}
	})
	admitted := decide.Decision{Module: "model", Route: &routes.Endpoints[0], Identity: hop.Identity{Owner: "maya", Tenant: "acme", Actors: []string{"wiki"}, Binding: "acme/wiki/model", Task: "task-1", Expires: time.Now().Add(time.Minute).Unix()}}
	t.Run("an admission the hop cannot sign", func(t *testing.T) {
		unsignable := admitted
		unsignable.Identity.Advisory = "the method's policy refused it"
		h := face(ready, func(context.Context, string, metadata.MD) (decide.Decision, error) { return unsignable, nil })
		if got := call(h); got != http.StatusUnauthorized {
			t.Fatalf("an admission that cannot be signed was answered %d", got)
		}
		// The authority checked this call: who it is for is proven.
		got := one(t, codes.Unauthenticated, "cannot be signed as admission")
		want := Refusal{Method: got.Method, Code: got.Code, Reason: got.Reason, Module: "model", Organization: "acme", Owner: "maya", Actor: "wiki", Binding: "acme/wiki/model", Task: "task-1"}
		if got != want {
			t.Fatalf("the refusal is %+v, want %+v", got, want)
		}
	})
	t.Run("a hop with no published admission key", func(t *testing.T) {
		h := face(func() bool { return false }, func(context.Context, string, metadata.MD) (decide.Decision, error) { return admitted, nil })
		if got := call(h); got != http.StatusServiceUnavailable {
			t.Fatalf("a hop with no admission key answered %d", got)
		}
		if got := one(t, codes.Unavailable, "no current admission-key publication lease"); got.Owner != "principal-owner" || !got.Claimed {
			t.Fatalf("the refusal does not identify the call: %+v", got)
		}
		if len(logged) != 0 {
			t.Fatalf("the log gained a line it never had: %q", logged)
		}
	})
	t.Run("an admitted call tells the sink nothing", func(t *testing.T) {
		h := face(ready, func(context.Context, string, metadata.MD) (decide.Decision, error) { return admitted, nil })
		if got := call(h); got != http.StatusOK || len(told) != 0 || len(logged) != 0 {
			t.Fatalf("an admitted call was answered %d; sink %+v, log %q", got, told, logged)
		}
	})
}
