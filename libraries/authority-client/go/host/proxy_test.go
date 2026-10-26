package host

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/core/resources"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

// proxied counts every connection made to the environment proxy this test
// binary installs before anything reads (and caches) the proxy environment.
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
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		_ = os.Setenv(key, "http://"+listener.Addr().String())
	}
	_ = os.Unsetenv("NO_PROXY")
	_ = os.Unsetenv("no_proxy")
	code := m.Run()
	_ = listener.Close()
	os.Exit(code)
}

// host.Dial itself never follows the environment proxy: the workload credential
// and the verifier's key reads go to the admitted address, or nowhere.
func TestDialNeverContactsAnEnvironmentProxy(t *testing.T) {
	t.Setenv(resources.WorkspaceConfigurationPrefix+"__AUTHORITY__ENDPOINT", "https://accounts.example.test:8443")
	before := proxied.Load()
	conn, target, err := Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, _ = healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{})
	if n := proxied.Load() - before; n != 0 {
		t.Fatalf("host.Dial to %s contacted the environment proxy %d times", target, n)
	}
}

// HTTPTransport never follows the environment proxy either, and the default
// transport (the control) does: the proxy environment is live in this binary.
func TestHTTPTransportNeverContactsAnEnvironmentProxy(t *testing.T) {
	get := func(transport http.RoundTripper) int32 {
		before := proxied.Load()
		client := &http.Client{Transport: transport, Timeout: 500 * time.Millisecond}
		if response, err := client.Get("http://documents.ns.svc.cluster.local:8080/"); err == nil {
			_ = response.Body.Close()
		}
		return proxied.Load() - before
	}
	if n := get(HTTPTransport()); n != 0 {
		t.Fatalf("HTTPTransport contacted the environment proxy %d times", n)
	}
	if n := get(http.DefaultTransport); n == 0 {
		t.Fatal(fmt.Sprint("control: the default transport did not reach the environment proxy, so this test proves nothing"))
	}
}

// The HTTP seam cannot be unwrapped into a *http.Transport to reconfigure.
func TestHTTPTransportCannotBeReconfigured(t *testing.T) {
	if _, ok := HTTPTransport().(*http.Transport); ok {
		t.Fatal("HTTPTransport exposes the shared *http.Transport")
	}
}
