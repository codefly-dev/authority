// The authority gateway, end to end: every plugin registered on one gRPC server over
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

	"gateway/pkg/business/state"
)

func TestTheMiniGatewayPassesTheSuiteEveryImplementationMustPass(t *testing.T) {
	k := testkit.New(t)
	plugins := []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer},
		&composition.Plugin{State: k.State, Verifier: testkit.ReleaseVerifier(t, "local"), Carrier: k.CarrierAuthority, Keys: testkit.ReleaseKeys()},
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
		Audience: "records", ReadKind: "records.records",
		WorkloadModule: "org-directory", WorkloadCredential: k.Credential(t, "org-directory"), Binding: "records", BindingAudience: "records", Elsewhere: "model",
		InstalledSolution: state.InstallationID("acme", "wiki"),
		// Deliveries are signed with the kit's release key and carried by the
		// module's own workload under the launcher.
		HostCoordinate: "local", HostDomain: "local",
		SignManifest:       testkit.SignDocument,
		SignAuthority:      testkit.SignAuthority,
		DeliveryCredential: func(module string) string { return k.Credential(t, module) },
		Matrix:             testkit.Matrix(),
		// Maya reads the directory's and the wiki's collections and every shared
		// one, and administers none: the authority's answer, not her token's.
		// The page may write documents for Rémi, and a lookup through it reads.
		Lookup: &conformance.LookupCase{Token: "fixture-remi", Start: "org-directory", Credential: k.Credential(t, "org-directory"),
			Binding: "documents", Audience: "documents", Kind: "documents", Invoke: "write", Lookup: "read"},
		// Rémi lets the page write documents for him; Maya, a viewer, cannot.
		Delegation: &conformance.DelegationCase{Token: "fixture-remi", Outsider: "fixture-maya", Module: "org-directory",
			Credential: k.Credential(t, "org-directory"), Binding: "documents", Audience: "documents", Kind: "documents", Action: "write"},
		Resources: &conformance.ResourceCase{
			Token: "fixture-maya", Audience: "documents", Kind: "documents.collection", Action: "read",
			Covered: []string{"derived\x1fdirectory", "derived\x1fwiki", "shared-finance"}, Uncovered: []string{"finance", "shared-Finance"}, Unheld: "admin",
		},
		// Rémi at the page; the page asks documents; documents asks the model,
		// for a read Rémi holds at the model and his first token never carried.
		Chain: &conformance.Chain{Token: "fixture-remi", Start: "org-directory", Hops: []conformance.Hop{
			{Credential: k.Credential(t, "org-directory"), Binding: "documents", Audience: "documents", AskKind: "documents", AskAction: "read"},
			{Credential: k.Credential(t, "documents"), Binding: "model", Audience: "model", AskKind: "modelservice.profiles", AskAction: "read"},
		}},
	})
}
