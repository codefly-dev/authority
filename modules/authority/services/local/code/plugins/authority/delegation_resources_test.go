package authority_test

import (
	"context"
	"net"
	"slices"
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

// A broad person and binding cannot expand a resource-limited delegation.
// Exercise the generated RPC client so response projection cannot lose IDs.
func TestDelegationKeepsResourceIDsAcrossItsLifecycle(t *testing.T) {
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
	granted, err := client.Delegate(person, &authorityv1.DelegateRequest{
		Module: "org-directory", Purpose: "bounded work",
		Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}, ResourceIds: []string{"a"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	check := func(scopes []*authorityv1.WorkScopeV1) {
		t.Helper()
		if len(scopes) != 1 || scopes[0].GetResourceKind() != "documents" ||
			!slices.Equal(scopes[0].GetActions(), []string{"write"}) ||
			!slices.Equal(scopes[0].GetResourceIds(), []string{"a"}) {
			t.Errorf("delegation widened: %v", scopes)
		}
	}
	check(granted.GetScopes())
	id := granted.GetDelegationId()
	actor := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}
	read, err := client.GetDelegation(context.Background(), &authorityv1.GetDelegationRequest{DelegationId: id, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	check(read.GetScopes())
	request := &authorityv1.IssueRequest{
		As:    &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: id}},
		Actor: actor, Audience: "documents", OperationBindingId: "documents",
	}
	issued, err := client.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	check(issued.GetContext().GetAuthorityScopes())
	checked, err := client.Check(context.Background(), &authorityv1.CheckRequest{Token: issued.GetToken(), Audience: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	check(checked.GetContext().GetAuthorityScopes())
	request.Scopes = []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}, ResourceIds: []string{"b"}}}
	if _, err := client.Issue(context.Background(), request); status.Code(err) != codes.PermissionDenied {
		t.Errorf("request outside delegated IDs must be refused: %v", err)
	}
	revoked, err := client.RevokeDelegation(person, &authorityv1.RevokeDelegationRequest{DelegationId: id})
	if err != nil {
		t.Fatal(err)
	}
	check(revoked.GetDelegation().GetScopes())
	if revoked.GetDelegation().GetActive() {
		t.Error("revoked delegation still active")
	}
	if _, err := client.Check(context.Background(), &authorityv1.CheckRequest{Token: issued.GetToken(), Audience: "documents"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("previously issued authority must be refused after revocation: %v", err)
	}
}
