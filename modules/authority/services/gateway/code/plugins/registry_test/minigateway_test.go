// The mini gateway, end to end: every plugin registered on one gRPC server over
// an in-memory connection, driven by the suite every implementation must pass.
package registry_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/testkit"
	"gateway/pkg/framework"
	"gateway/plugins/authority"
	"gateway/plugins/composition"
	"gateway/plugins/installation"
	"gateway/plugins/session"
	conformance "github.com/codefly-dev/authority/libraries/conformance/go"
)

func TestTheMiniGatewayPassesTheSuiteEveryImplementationMustPass(t *testing.T) {
	k := testkit.New(t)
	plugins := []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer},
		&composition.Plugin{State: k.State, Verifier: testkit.ReleaseVerifier(t, "local"), Carrier: k.CarrierAuthority},
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
	_, file, _, _ := runtime.Caller(0)
	descriptors, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "..", "..", "libraries", "authority-client", "contract", "contract.binpb"))
	if err != nil {
		t.Fatal(err)
	}
	conformance.Run(t, conn, descriptors, conformance.Fixture{
		Organization: "acme", ViewerToken: "fixture-maya", AdminToken: "fixture-alex",
		// Maya reads records; the directory page hops on her context through its
		// records binding; a context at records is refused at model.
		Audience: "records", ReadKind: "records.record",
		WorkloadModule: "org-directory", WorkloadCredential: k.Credential(t, "org-directory"), Binding: "records", BindingAudience: "records", Elsewhere: "model",
		InstalledSolution: "acme/wiki",
		// Deliveries are signed with the kit's release key and carried by the
		// module's own workload under the launcher.
		HostCoordinate: "local", HostDomain: "local",
		SignManifest:       testkit.SignDocument,
		DeliveryCredential: func(module string) string { return k.Credential(t, module) },
		Matrix:             testkit.Matrix(),
	})
}
