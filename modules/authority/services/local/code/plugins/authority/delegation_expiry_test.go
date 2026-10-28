package authority_test

import (
	"context"
	"net"
	"testing"

	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	authorityplugin "gateway/plugins/authority"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// A lifetime asked for on the wire reaches the delegation, and both the
// grantor's answer and the module's read carry when it ends; none asked
// carries none.
func TestADelegationsLifetimeCrossesTheWire(t *testing.T) {
	k := testkit.New(t)
	server := grpc.NewServer()
	(&authorityplugin.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
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
	client := authorityv1.NewAuthorityServiceClient(conn)
	session, err := k.State.SignIn("fixture-remi")
	if err != nil {
		t.Fatal(err)
	}
	person := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+session.ID))
	actor := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}
	delegate := func(ttl int64) *authorityv1.Delegation {
		t.Helper()
		d, err := client.Delegate(person, &authorityv1.DelegateRequest{Module: "org-directory", Purpose: "one run", TtlSeconds: ttl,
			Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}}}})
		if err != nil {
			t.Fatal(err)
		}
		read, err := client.GetDelegation(context.Background(), &authorityv1.GetDelegationRequest{DelegationId: d.GetDelegationId(), Actor: actor})
		if err != nil || read.GetExpiresAtUnix() != d.GetExpiresAtUnix() || !read.GetActive() {
			t.Fatalf("the module reads %+v, the grantor was answered %+v (%v)", read, d, err)
		}
		return d
	}

	hour := delegate(3600)
	if at := hour.GetExpiresAtUnix() - k.Now.Unix(); at < 3600 || at > 3600+60 {
		t.Fatalf("a one-hour delegation ends %d s after the kit's start", at)
	}
	if open := delegate(0); open.GetExpiresAtUnix() != 0 {
		t.Fatalf("a delegation asked for with no lifetime ends at %d", open.GetExpiresAtUnix())
	}

	// Seconds that overflow a Duration once multiplied (2^55 s wraps to 0 ns)
	// are a lifetime past the ceiling, never one that stands until revoked;
	// their negative is refused (review of #50).
	huge := delegate(1 << 55)
	if at := huge.GetExpiresAtUnix() - k.Now.Unix(); at < 7*24*3600 || at > 7*24*3600+60 {
		t.Fatalf("2^55 s ends %d s after the kit's start, want the seven-day ceiling", at)
	}
	if _, err := client.Delegate(person, &authorityv1.DelegateRequest{Module: "org-directory", Purpose: "one run", TtlSeconds: -(1 << 55),
		Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("-2^55 s: %v", err)
	}
}
