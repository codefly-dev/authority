package authority_test

import (
	"context"
	"net"
	"strings"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	authorityplugin "gateway/plugins/authority"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// Probe the actual generated client, plugin and issuer together. The existing
// testkit owns the fixture identity/signing; this test adds no second issuer.
func TestGeneratedCheckReportsAdvisoryWithoutChangingIdentity(t *testing.T) {
	k := testkit.New(t)
	manifest := testkit.Documents(2)
	manifest.Methods = map[string]state.MethodPolicy{
		"/documents.v1.Documents/Read":  {Requires: []*basev0.WorkScopeV1{testkit.Scope("documents", "read")}},
		"/documents.v1.Documents/Write": {Requires: []*basev0.WorkScopeV1{testkit.Scope("documents", "write")}},
	}
	if _, err := k.State.ApplyManifest(manifest); err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	(&authorityplugin.Plugin{Issuer: k.Issuer}).RegisterGRPC(server)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := authorityv1.NewAuthorityServiceClient(connection)
	session, err := k.State.SignIn("fixture-maya")
	if err != nil {
		t.Fatal(err)
	}
	person := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+session.ID))
	issued, err := client.Issue(person, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"/documents.v1.Documents/Write", "/documents.v1.Documents/Undeclared"} {
		t.Run(method, func(t *testing.T) {
			request := &authorityv1.CheckRequest{Token: issued.GetToken(), Audience: "documents", Method: method}
			if _, err := client.Check(context.Background(), request); err == nil {
				t.Fatal("strict check did not refuse")
			}
			request.Advisory = true
			response, err := client.Check(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if response.GetRefusal() == "" {
				t.Fatal("warning missing")
			}
			if !proto.Equal(response.GetContext(), issued.GetContext()) {
				t.Fatal("advisory changed issued identity/scopes")
			}
		})
	}
	allowed, err := client.Check(context.Background(), &authorityv1.CheckRequest{
		Token: issued.GetToken(), Audience: "documents", Method: "/documents.v1.Documents/Read", Advisory: true})
	if err != nil || strings.TrimSpace(allowed.GetRefusal()) != "" {
		t.Fatalf("allowed read: %v, %v", allowed, err)
	}
}
