// The mini gateway, end to end: every plugin registered on one gRPC server over
// an in-memory connection, driven by the suite every implementation must pass.
package registry_test

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/testkit"
	"gateway/pkg/conformance"
	"gateway/pkg/framework"
	"gateway/plugins/authority"
	"gateway/plugins/composition"
	"gateway/plugins/installation"
	"gateway/plugins/session"
)

func TestTheMiniGatewayPassesTheSuiteEveryImplementationMustPass(t *testing.T) {
	k := testkit.New(t)
	plugins := []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer}, &composition.Plugin{State: k.State},
		&installation.Plugin{State: k.State}, &session.Plugin{State: k.State},
	}
	server := grpc.NewServer()
	for _, p := range plugins {
		p.RegisterGRPC(server)
	}
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	conformance.Run(t, conn, conformance.Fixture{
		Organization: "acme", ViewerToken: "fixture-maya", AdminToken: "fixture-alex",
		Audience: "documents", ReadKind: "documents",
		WorkloadCredential: k.Credential(t, "documents"), Binding: "model", BindingAudience: "model",
		InstalledSolution: "acme/wiki",
	})
}
