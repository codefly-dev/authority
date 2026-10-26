package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/authority/libraries/hop/go/routing"
	"google.golang.org/grpc/metadata"

	"hop/pkg/business/decide"
)

// proxied counts connections to the HTTP proxy this test binary installs before
// anything reads (and caches) the proxy environment. Only HTTP_PROXY is set: it
// governs http:// requests, and leaves the gRPC tests' dials untouched.
var proxied atomic.Int32

func TestMain(m *testing.M) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			proxied.Add(1)
			_ = conn.Close()
		}
	}()
	for _, key := range []string{"HTTP_PROXY", "http_proxy"} {
		_ = os.Setenv(key, "http://"+listener.Addr().String())
	}
	_ = os.Unsetenv("NO_PROXY")
	_ = os.Unsetenv("no_proxy")
	code := m.Run()
	_ = listener.Close()
	os.Exit(code)
}

// The hop's HTTP face forwards a decided request (stamp, proof, Work Context) to
// the module directly, never through the environment proxy.
func TestTheHTTPFaceNeverForwardsThroughAnEnvironmentProxy(t *testing.T) {
	target, _ := url.Parse("http://documents.ns.svc.cluster.local:8080")
	h := &HTTP{
		Proof:     "run-proof",
		Upstreams: map[string]*url.URL{target.String(): target},
		Decide: func(context.Context, string, metadata.MD) (decide.Decision, error) {
			return decide.Decision{Route: &routing.RouteEndpoint{Address: target.String()}, Module: "documents", Identity: hop.Identity{Owner: "maya", Tenant: "acme"}}, nil
		},
	}
	before := proxied.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/v1/documents", nil).WithContext(ctx)
	req.Header.Set(hop.WorkContextKey, "SECRET-WC")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if n := proxied.Load() - before; n != 0 {
		t.Fatalf("the hop forwarded the Work Context through the environment proxy (%d connections)", n)
	}
}
