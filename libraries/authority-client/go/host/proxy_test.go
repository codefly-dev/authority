package host

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

// A dial to the authority never follows a proxy from the environment: the
// workload credential and the verifier's key reads go to the address the
// transport rule admitted, or nowhere.
func TestTheDialNeverContactsAnEnvironmentProxy(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	var contacted atomic.Int32
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			contacted.Add(1)
			_ = conn.Close()
		}
	}()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "http://"+proxy.Addr().String())
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	conn, err := grpc.NewClient("documents.ns.svc.cluster.local:8080", DialOptions(insecure.NewCredentials())...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, _ = healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{})
	if n := contacted.Load(); n != 0 {
		t.Fatalf("the dial contacted the environment proxy %d times", n)
	}
}
