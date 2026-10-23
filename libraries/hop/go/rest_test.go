package hop

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

// Whatever address the gateway was told, the connection reaches the hop.
func TestARESTGatewayDialsTheHopWhateverItsTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	healthv1.RegisterHealthServer(server, health.NewServer())
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///0.0.0.0:1", RESTThroughHop("grpc://"+listener.Addr().String()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := healthv1.NewHealthClient(conn).Check(context.Background(), &healthv1.HealthCheckRequest{}); err != nil {
		t.Fatalf("the call did not reach the hop: %v", err)
	}
}
