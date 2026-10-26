package registry_test

import (
	"context"
	"github.com/google/uuid"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"connectrpc.com/vanguard/vanguardgrpc"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	"gateway/pkg/gen/host/installation/v1/installationv1connect"
	"gateway/plugins/installation"
	"google.golang.org/grpc"
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
	handler, err := vanguardgrpc.NewTranscoder(server)
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(handler)
	t.Cleanup(web.Close)
	t.Cleanup(server.Stop)
	client := installationv1connect.NewInstallationServiceClient(web.Client(), web.URL)
	req := &installationv1.InstallRequest{OrganizationId: "acme", Target: "proposals", Role: "viewer", OwnerPersonId: "alex"}
	for _, bearer := range []string{"", "not-a-session"} {
		request := connect.NewRequest(req)
		if bearer != "" {
			request.Header().Set("Authorization", "Bearer "+bearer)
		}
		_, err := client.Install(t.Context(), request)
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
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
	review := connect.NewRequest(&installationv1.ReviewRequest{OrganizationId: req.OrganizationId, Target: req.Target})
	review.Header().Set("Authorization", "Bearer "+sess.ID)
	offered, err := client.Review(t.Context(), review)
	if err != nil {
		t.Fatal(err)
	}
	req.Approval = offered.Msg
	req.Approval.OperationId = uuid.NewString()
	install := func() (*connect.Response[installationv1.Installation], error) {
		request := connect.NewRequest(req)
		request.Header().Set("Authorization", "Bearer "+sess.ID)
		return client.Install(t.Context(), request)
	}
	first, err := install()
	if err != nil {
		t.Fatal(err)
	}
	retry, err := install()
	if err != nil || retry.Msg.GetId() != first.Msg.GetId() {
		t.Fatalf("unchanged retry: %v", err)
	}
	req.Role = "installer"
	if _, err := install(); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("changed request: %v", err)
	}
	if steps.Load() != 1 {
		t.Fatalf("authenticated install steps: %d", steps.Load())
	}
}
