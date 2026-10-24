package registry_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	conformance "github.com/codefly-dev/authority/libraries/conformance/go"

	"gateway/pkg/business/state"
)

// TestARunningMiniGatewayPassesTheSuite drives the suite against a authority gateway
// started by codefly run, at the gRPC address AUTHORITY_GRPC_ADDR names. The
// lines that need the launcher's credential for a workload are red here, since
// only the run's launcher mints one; everything a person does is proven live.
func TestARunningMiniGatewayPassesTheSuite(t *testing.T) {
	addr := os.Getenv("AUTHORITY_GRPC_ADDR")
	if addr == "" {
		t.Skip("set AUTHORITY_GRPC_ADDR to the running authority gateway's gRPC address")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		Audience: "records", ReadKind: "records.records", Elsewhere: "model",
		WorkloadModule: "org-directory", Binding: "records", BindingAudience: "records",
		InstalledSolution: state.InstallationID("acme", "wiki"),
	})
}
