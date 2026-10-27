// The artifact interface (conformance RunArtifacts), against the local
// authority: run with every go test.
package registry_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	"gateway/pkg/framework"
	"gateway/plugins/artifact"
	"gateway/plugins/authority"
	"gateway/plugins/installation"
	"gateway/plugins/session"

	conformance "github.com/codefly-dev/authority/libraries/conformance/go"
)

func TestTheLocalAuthorityDecidesArtifactsAsEveryHostMust(t *testing.T) {
	k := testkit.New(t)
	// A module installed at Acme alone: the probe module the kit's launcher
	// declares for the suite, composed here and nowhere else in this kit. Its
	// installed artifact policy is a resource kind it serves. An administrator
	// and a member who is not one hold its activate and run actions through a
	// role; another member holds run alone.
	const module, policy = "conformance-probe", "conformance-probe.intent"
	if _, err := k.State.ApplyManifest(state.Manifest{Name: module, Principal: module, Kind: "module", Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope(policy, "activate", "run")}, Bindings: map[string]state.Binding{}}); err != nil {
		t.Fatal(err)
	}
	if err := k.State.UninstallAsHost(state.InstallationID("globex", module)); err != nil {
		t.Fatal(err)
	}
	if err := k.State.LoadFixture(context.Background(), []byte(`roles:
  - organization: acme
    name: artifact-approver
    scopes:
      - {kind: conformance-probe.intent, actions: [activate, run]}
  - organization: acme
    name: artifact-runner
    scopes:
      - {kind: conformance-probe.intent, actions: [run]}
people:
  - {id: artifact-admin, fixture_token: fixture-artifact-admin, organization: acme, roles: [admin, artifact-approver]}
  - {id: artifact-approver, fixture_token: fixture-artifact-approver, organization: acme, roles: [artifact-approver]}
  - {id: artifact-runner, fixture_token: fixture-artifact-runner, organization: acme, roles: [artifact-runner]}
`)); err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	for _, p := range []framework.Plugin{
		&authority.Plugin{Issuer: k.Issuer}, &artifact.Plugin{Issuer: k.Issuer},
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
	conformance.RunArtifacts(t, conn, descriptors, conformance.ArtifactCase{
		Module: module, Credential: k.Credential(t, module), OtherCredential: k.Credential(t, "documents"), Policy: policy,
		Admin: "fixture-artifact-admin", Approver: "fixture-artifact-approver", Member: "fixture-artifact-runner", OtherAdmin: "fixture-zoe",
	})
}
