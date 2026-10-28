package forward_test

import (
	"bufio"
	"context"
	"fmt"
	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/decide"
	"github.com/codefly-dev/authority/libraries/hop/go/forward"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc/metadata"
)

func TestNonCanonicalPathsRefuseBeforeDecisionOverRawHTTP(t *testing.T) {
	var checked, forwarded atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(204) }))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	face := &forward.HTTP{Signer: hoptest.Signer("test-proof"), Ready: published(t, hoptest.Signer("test-proof")), Upstreams: map[string]*url.URL{backend.URL: target}, Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
		checked.Add(1)
		return decide.Decision{Module: "module", Route: &routing.RouteEndpoint{Address: backend.URL}, Identity: hop.Identity{Expires: time.Now().Add(time.Minute).Unix(), Owner: "person", Tenant: "tenant"}}, nil
	}}
	server := httptest.NewServer(face)
	defer server.Close()
	for _, path := range []string{"/v1/projects/../secrets", "/v1/projects/./secrets", "/v1//secrets", "/v1/projects/%2e%2e/secrets", "/v1/projects/%2E/secrets", "/v1/projects%2f..%2Fsecrets", "/v1/projects/%252e%252e/secrets", "/v1/projects/%5csecrets"} {
		t.Run(path, func(t *testing.T) {
			conn, err := net.Dial("tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: hop.test\r\nConnection: close\r\n\r\n", path)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != 400 || !strings.Contains(string(body), "non-canonical request path") {
				t.Fatalf("status %d reason %s", response.StatusCode, body)
			}
		})
	}
	if checked.Load() != 0 || forwarded.Load() != 0 {
		t.Fatalf("unsafe paths checked=%d forwarded=%d", checked.Load(), forwarded.Load())
	}
}

func TestHTTPInventoryCannotReplaceTheAuthoritysConcretePolicy(t *testing.T) {
	checker := &routeChecker{denied: "GET /v1/things/export"}
	routes := &routing.Routing{Endpoints: []routing.RouteEndpoint{routeEndpoint("web", "http", "unused", "GET /v1/things/{id}")}}
	d := decide.Decider{Routes: routes, Authority: checker, Modules: map[string]bool{"module": true}, AudienceOf: func(string) (string, error) { return "module", nil }}
	_, err := d.Decide(context.Background(), "GET /v1/things/export", metadata.Pairs(hop.WorkContextKey, "context"))
	if err == nil || len(checker.calls) != 1 || checker.calls[0] != "GET /v1/things/export" {
		t.Fatalf("literal policy bypassed: checked=%v error=%v", checker.calls, err)
	}
	// A manifest ambiguity must reach the authority as the concrete path too.
	checker.failure = fmt.Errorf("manifest has ambiguous routes")
	_, err = d.Decide(context.Background(), "GET /v1/things/item", metadata.Pairs(hop.WorkContextKey, "context"))
	if err == nil || checker.calls[1] != "GET /v1/things/item" {
		t.Fatalf("ambiguity bypassed: checked=%v error=%v", checker.calls, err)
	}
}
