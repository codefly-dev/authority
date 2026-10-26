// The solution-principal target, against the local authority. It is the
// contract the local authority does not meet yet (conformance
// RunSolutionPrincipalTarget): run it with AUTHORITY_TARGET=solution-principal
// and it fails, naming what the published contract lacks first.
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

func TestTheLocalAuthorityMeetsTheSolutionPrincipalTarget(t *testing.T) {
	if os.Getenv("AUTHORITY_TARGET") != "solution-principal" {
		t.Skip("target contract, not yet implemented: run with AUTHORITY_TARGET=solution-principal to see what it lacks")
	}
	k := testkit.New(t)
	// Two people whose own organisation grants reach one existing resource of
	// the store's kind (one administers it, one reads it), and a member of a
	// team no installation is granted to.
	if err := k.State.LoadFixture(context.Background(), []byte(`roles:
  - organization: acme
    name: principal-store-admin
    scopes:
      - {kind: principal.collection, actions: [admin], resources: [{id: store-x}]}
  - organization: acme
    name: principal-store-reader
    scopes:
      - {kind: principal.collection, actions: [read], resources: [{id: store-x}]}
people:
  - id: store-administrator
    fixture_token: fixture-store-administrator
    organization: acme
    roles: [principal-store-admin]
  - id: store-reader
    fixture_token: fixture-store-reader
    organization: acme
    roles: [principal-store-reader]
  - id: principal-team-member
    fixture_token: fixture-principal-team-member
    organization: acme
    roles: []
    teams: [principal-team]
`)); err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	for _, p := range []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer},
		&composition.Plugin{State: k.State, Coordinate: "local", Verifier: testkit.ReleaseVerifier(t, "local"), Carrier: k.CarrierAuthority, Keys: testkit.ReleaseKeys()},
		&installation.Plugin{State: k.State}, &session.Plugin{State: k.State},
	} {
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
	conformance.RunSolutionPrincipalTarget(t, conn, descriptors, conformance.SolutionPrincipalCase{
		Organization: "acme", Generation: 1,
		A:     conformance.SolutionUnderTest{Solution: "principal-a", Credential: k.Credential(t, "principal-a")},
		B:     conformance.SolutionUnderTest{Solution: "principal-b", Credential: k.Credential(t, "principal-b")},
		Store: "principal-store", StoreCredential: k.Credential(t, "principal-store"), Kind: "principal.collection",
		Admin: "fixture-alex", Viewer: "fixture-maya", Editor: "fixture-remi", Member: "fixture-dev",
		Administrator: "fixture-store-administrator", Reader: "fixture-store-reader", Existing: "store-x",
		Team: "principal-team", TeamMember: "fixture-principal-team-member",
		Uninstall:          func(_ context.Context, id string) error { return k.State.Revoke(id) },
		SignManifest:       testkit.SignDocument,
		SignAuthority:      testkit.SignAuthority,
		DeliveryCredential: func(module string) string { return k.Credential(t, module) },
		HostCoordinate:     "local", HostDomain: "local",
	})
}
