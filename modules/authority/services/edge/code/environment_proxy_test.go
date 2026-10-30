package main

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
)

// proxied counts connections to the HTTP proxy this test binary installs before
// anything reads (and caches) the proxy environment.
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

// The edge sends a person's Work Context to the module directly, never through
// the environment proxy (review r89 B1: a proxy read X-Codefly-Work-Context).
func TestTheEdgeNeverForwardsThePersonsWorkContextThroughAnEnvironmentProxy(t *testing.T) {
	target, _ := url.Parse("http://documents.ns.svc.cluster.local:8080")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	before := proxied.Load()
	proxy(target, "SECRET-WC", "", httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/documents", nil).WithContext(ctx))
	if n := proxied.Load() - before; n != 0 {
		t.Fatalf("the edge forwarded the Work Context through the environment proxy (%d connections)", n)
	}
}
