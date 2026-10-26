package registry_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	"gateway/plugins/installation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestUnauthenticatedRequestCannotReachHostInstallation(t *testing.T) {
	k := testkit.New(t)
	if _, err := k.State.ApplyManifest(testkit.Proposals(1)); err != nil {
		t.Fatal(err)
	}
	var steps atomic.Int32
	k.State.OnInstall(func(context.Context, state.Installation) error { steps.Add(1); return nil })
	server := grpc.NewServer()
	(&installation.Plugin{State: k.State}).RegisterGRPC(server)
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
	// This contract generates a gRPC client, not a Connect client.
	client := installationv1.NewInstallationServiceClient(conn)
	req := &installationv1.InstallRequest{OrganizationId: "acme", Target: "proposals", Role: "viewer", OwnerPersonId: "alex"}
	for _, bearer := range []string{"", "not-a-session"} {
		ctx := t.Context()
		if bearer != "" {
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+bearer))
		}
		_, err := client.Install(ctx, req)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("bearer %q: %v", bearer, err)
		}
		if _, exists := k.State.Installation(state.InstallationID("acme", "proposals")); exists {
			t.Fatal("unauthenticated request installed solution")
		}
		if steps.Load() != 0 {
			t.Fatal("unauthenticated request reached host install step")
		}
	}
	// A real administrator can execute the same request through the same client.
	sess, err := k.State.SignIn("fixture-alex")
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("authorization", "Bearer "+sess.ID))
	if _, err := client.Install(ctx, req); err != nil {
		t.Fatal(err)
	}
	if steps.Load() != 1 {
		t.Fatalf("authenticated install steps: %d", steps.Load())
	}
}
