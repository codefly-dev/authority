package forward

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// stalling is an authority that answers at once, or not at all for as long as
// the hop waits for it.
type stalling struct {
	stalled atomic.Bool
	asked   atomic.Int64
}

func (s *stalling) Check(ctx context.Context, _ *authorityv1.CheckRequest, _ ...grpc.CallOption) (*authorityv1.CheckResponse, error) {
	s.asked.Add(1)
	if s.stalled.Load() {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &authorityv1.CheckResponse{Context: &authorityv1.WorkContextV1{OwnerPrincipalId: "maya", TenantId: "acme", ExpiresAtUnix: time.Now().Add(time.Minute).Unix()}}, nil
}

// Review item A7: an authority that does not answer inside the hop's own
// deadline fails the call closed. The caller, which set no deadline, is
// answered 503 at that deadline; nothing is forwarded; and nothing is kept,
// so neither the failure nor an earlier admission answers the next call.
func TestAnAuthorityThatDoesNotAnswerInTimeFailsTheCallClosed(t *testing.T) {
	var reached atomic.Int64
	module := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer module.Close()
	target, _ := url.Parse(module.URL)
	authority := &stalling{}
	h := &HTTP{
		Signer: hoptest.Signer("deadline"), Ready: published(t, hoptest.Signer("deadline")),
		Upstreams: map[string]*url.URL{target.String(): target},
		Decide: decide.Decider{Authority: authority, Timeout: 200 * time.Millisecond, Modules: map[string]bool{"model": true},
			AudienceOf: func(string) (string, error) { return "model", nil },
			Routes:     &routing.Routing{Endpoints: []routing.RouteEndpoint{{Audience: "model", Transport: "http", Address: target.String(), Methods: []string{"GET /v1/model/profiles"}}}},
		}.Decide,
	}
	call := func() (*httptest.ResponseRecorder, time.Duration) {
		req := httptest.NewRequest(http.MethodGet, "/v1/model/profiles", nil) // no deadline of the caller's
		req.Header.Set(hop.WorkContextKey, "wc-model")
		rec := httptest.NewRecorder()
		started := time.Now()
		h.ServeHTTP(rec, req)
		return rec, time.Since(started)
	}

	if rec, _ := call(); rec.Code != http.StatusOK || reached.Load() != 1 {
		t.Fatalf("an answering authority: %d %s, reached %d", rec.Code, rec.Body.String(), reached.Load())
	}
	// The same caller, the same Work Context, an authority that stalls: the
	// admission a moment ago answers nothing.
	authority.stalled.Store(true)
	rec, took := call()
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "authority") {
		t.Fatalf("a stalled authority was answered %d %s", rec.Code, rec.Body.String())
	}
	if took > 5*time.Second {
		t.Fatalf("the caller waited %v on a stalled authority", took)
	}
	if reached.Load() != 1 {
		t.Fatal("a call the authority never checked was forwarded")
	}
	// The failure is not kept either: the authority answers again, and so does the call.
	authority.stalled.Store(false)
	if rec, _ := call(); rec.Code != http.StatusOK || reached.Load() != 2 || authority.asked.Load() != 3 {
		t.Fatalf("after the authority recovered: %d %s, reached %d, asked %d", rec.Code, rec.Body.String(), reached.Load(), authority.asked.Load())
	}
}
