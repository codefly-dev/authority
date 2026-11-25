// The access interface (conformance RunAccess), against the local authority:
// run with every go test.
package registry_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/testkit"
	"gateway/pkg/framework"
	"gateway/plugins/access"
	"gateway/plugins/authority"
	"gateway/plugins/composition"
	"gateway/plugins/installation"
	"gateway/plugins/session"

	conformance "github.com/codefly-dev/authority/libraries/conformance/go"
)

func TestTheLocalAuthorityPassesTheAccessSuite(t *testing.T) {
	// A host of its own, on a clock of its own: it runs beside the other
	// suites of this package, which each build theirs.
	t.Parallel()
	conn, descriptors, f := accessHost(t)
	conformance.RunAccess(t, conn, descriptors, f)
}

// The local authority serves revision minimums: a decision asked with one is
// never read from an earlier state, even while its reader is held behind.
func TestTheLocalAuthorityPassesTheAccessRevisionSuite(t *testing.T) {
	// A host of its own, on a clock of its own: it runs beside the other
	// suites of this package, which each build theirs.
	t.Parallel()
	conn, descriptors, f := accessHost(t)
	conformance.RunAccessRevisions(t, conn, descriptors, f)
}

// accessHost is a local authority of its own serving the access interface,
// and the fixture the access suites run on.
func accessHost(t *testing.T) (*grpc.ClientConn, []byte, conformance.AccessCase) {
	t.Helper()
	// The suite moves the host's clock to pass a grant's expiry: the kit's
	// own readable epoch, advancing with the wall clock, plus what it asked.
	epoch, started := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC), time.Now()
	var advanced atomic.Int64
	k := testkit.NewWithClock(t, func() time.Time {
		return epoch.Add(time.Since(started) + time.Duration(advanced.Load()))
	})
	if err := k.State.LoadFixture(context.Background(), []byte(`people:
  - {id: access-reader, fixture_token: fixture-access-reader, organization: acme, roles: []}
  - {id: access-admin, fixture_token: fixture-access-admin, organization: acme, roles: []}
  - {id: access-team-member, fixture_token: fixture-access-team-member, organization: acme, roles: [], teams: [access-team]}
  - {id: access-team-leaver, fixture_token: fixture-access-team-leaver, organization: acme, roles: [], teams: [access-team]}
  - {id: access-org-leaver, fixture_token: fixture-access-org-leaver, organization: acme, roles: []}
`)); err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	for _, p := range []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer}, &access.Plugin{Issuer: k.Issuer},
		&composition.Plugin{State: k.State, Coordinate: "local", Verifier: testkit.ReleaseVerifier(t, "local"), Carrier: k.CarrierAuthority, Keys: testkit.ReleaseKeys()},
		&installation.Plugin{State: k.State}, &session.Plugin{State: k.State, Fixture: true},
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
	return conn, descriptors, conformance.AccessCase{
		SolutionPrincipalCase: conformance.SolutionPrincipalCase{
			Organization: "acme", OtherOrganization: "globex", Generation: 1,
			A:     conformance.SolutionUnderTest{Solution: "principal-a", Credential: k.Credential(t, "principal-a")},
			B:     conformance.SolutionUnderTest{Solution: "principal-b", Credential: k.Credential(t, "principal-b")},
			C:     conformance.SolutionUnderTest{Solution: "principal-c", Credential: k.Credential(t, "principal-c")},
			Store: "principal-store", StoreCredential: k.Credential(t, "principal-store"), Kind: "principal.document",
			Admin: "fixture-alex", UserHolder: "fixture-maya", Author: "fixture-remi", Member: "fixture-dev", AdminHolder: "fixture-access-admin",
			Team: "access-team", TeamMember: "fixture-access-team-member", TeamLeaver: "fixture-access-team-leaver", OrgLeaver: "fixture-access-org-leaver",
			Reader:     "fixture-access-reader",
			OtherAdmin: "fixture-zoe", OtherMember: "fixture-omar",
			Uninstall:              func(_ context.Context, id string) error { return k.State.UninstallAsHost(id) },
			RemoveFromOrganization: k.State.LeaveOrganization,
			SignManifest:           testkit.SignDocument,
			SignAuthority:          testkit.SignAuthority,
			DeliveryCredential:     func(module string) string { return k.Credential(t, module) },
			HostCoordinate:         "local", HostDomain: "local",
		},
		CollectionKind: "principal.collection",
		// The local authority serves revision minimums, over a reader only a
		// test holds behind its store.
		MinRevision: true,
		Lag:         func(*testing.T) func() { return k.State.FreezeAccessReads() },
		Advance: func(_ context.Context, d time.Duration) error {
			advanced.Add(int64(d))
			return nil
		},
	}
}
