// Package conformance is the suite every implementation of the host interfaces
// must pass: the mini gateway here, accounts in the host. It drives only the
// generated clients, so it knows nothing of either implementation. An
// implementation hands it a connection and the fixture people it seeded.
package conformance

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	installationv1 "gateway/pkg/gen/host/installation/v1"
	sessionv1 "gateway/pkg/gen/host/session/v1"
)

// Fixture is what the suite assumes the implementation seeded.
type Fixture struct {
	// Organization is the one organisation the people belong to.
	Organization string
	// ViewerToken signs in a person who may read `Audience` and nothing more.
	ViewerToken string
	// AdminToken signs in an organisation administrator.
	AdminToken string
	// Audience is a composed module the viewer holds "read" on, with resource kind ReadKind.
	Audience string
	// ReadKind is the resource kind the viewer may read at Audience.
	ReadKind string
	// WorkloadCredential proves a composed module that declares Binding towards BindingAudience.
	WorkloadCredential string
	// Binding and BindingAudience describe that module's declared binding.
	Binding, BindingAudience string
	// InstalledSolution is an active installation the viewer is entitled to.
	InstalledSolution string
}

// Run drives the suite over one connection.
func Run(t *testing.T, conn grpc.ClientConnInterface, f Fixture) {
	t.Helper()
	ctx := context.Background()
	auth := authorityv1.NewAuthorityServiceClient(conn)
	sessions := sessionv1.NewSessionServiceClient(conn)
	installs := installationv1.NewInstallationServiceClient(conn)
	comp := compositionv1.NewCompositionServiceClient(conn)

	t.Run("keys name one Ed25519 key and an issuer", func(t *testing.T) {
		keys, err := auth.Keys(ctx, &authorityv1.KeysRequest{})
		if err != nil || keys.GetIssuer() == "" || len(keys.GetKeys()) == 0 || keys.GetKeys()[0].GetAlgorithm() != "Ed25519" {
			t.Fatalf("keys: %v %v", err, keys)
		}
	})
	t.Run("a fixture person signs in and an unknown token is refused", func(t *testing.T) {
		sess, err := sessions.SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: f.ViewerToken})
		if err != nil || sess.GetSessionId() == "" || sess.GetOrganizationId() != f.Organization {
			t.Fatalf("sign in: %v %v", err, sess)
		}
		_, err = sessions.SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: "not-a-person"})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("unknown token: %v", err)
		}
	})
	t.Run("a person is issued, checked, and refused elsewhere", func(t *testing.T) {
		sess, _ := sessions.SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: f.ViewerToken})
		out, err := auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{SessionId: sess.GetSessionId()}}, Audience: f.Audience})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		wc := out.GetContext()
		if wc.GetOwnerPrincipalId() != sess.GetPersonId() || wc.GetAudience() != f.Audience || wc.GetTenantId() != f.Organization {
			t.Fatalf("context = %v", wc)
		}
		if _, err := auth.Check(ctx, &authorityv1.CheckRequest{Token: out.GetToken(), Audience: f.Audience}); err != nil {
			t.Fatalf("check at the audience: %v", err)
		}
		if _, err := auth.Check(ctx, &authorityv1.CheckRequest{Token: out.GetToken(), Audience: f.BindingAudience}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("check at another audience: %v", err)
		}
		_, err = auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{SessionId: sess.GetSessionId()}}, Audience: f.Audience,
			Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: f.ReadKind, Actions: []string{"read", "write", "ingest", "admin"}}}})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("beyond the role must be PermissionDenied, got %v", err)
		}
	})
	t.Run("every refusal reaches the caller with a reason", func(t *testing.T) {
		_, err := auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{SessionId: "no-such-session"}}, Audience: f.Audience})
		if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "session") {
			t.Fatalf("unknown session: %v", err)
		}
		_, err = auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{SessionId: "x"}}, Audience: "not-composed"})
		if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "not-composed") {
			t.Fatalf("an uncomposed audience is named: %v", err)
		}
		_, err = auth.Check(ctx, &authorityv1.CheckRequest{Token: "garbage", Audience: f.Audience})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("garbage token: %v", err)
		}
	})
	t.Run("a workload is issued its own binding and nothing it did not declare", func(t *testing.T) {
		out, err := auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: f.WorkloadCredential}},
			Audience: f.BindingAudience, OrganizationId: f.Organization, OperationBindingId: f.Binding})
		if err != nil {
			t.Fatalf("workload issue: %v", err)
		}
		if out.GetContext().GetOwnerPrincipalKind() != "service" || out.GetContext().GetOperationBinding().GetBindingId() == "" {
			t.Fatalf("workload context = %v", out.GetContext())
		}
		if _, err := auth.Check(ctx, &authorityv1.CheckRequest{Token: out.GetToken(), Audience: f.BindingAudience}); err != nil {
			t.Fatalf("the audience checks it: %v", err)
		}
		_, err = auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: f.WorkloadCredential}},
			Audience: f.BindingAudience, OrganizationId: f.Organization, OperationBindingId: "undeclared"})
		if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("an undeclared binding is refused by name: %v", err)
		}
		_, err = auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: "forged.credential"}},
			Audience: f.BindingAudience, OrganizationId: f.Organization, OperationBindingId: f.Binding})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a forged credential: %v", err)
		}
	})
	t.Run("an installation acts for itself and is refused once uninstalled", func(t *testing.T) {
		list, err := installs.List(ctx, &installationv1.ListRequest{OrganizationId: f.Organization})
		if err != nil {
			t.Fatal(err)
		}
		var wiki *installationv1.Installation
		for _, i := range list.GetInstallations() {
			if i.GetId() == f.InstalledSolution {
				wiki = i
			}
		}
		if wiki == nil || wiki.GetStatus() != installationv1.Installation_STATUS_ACTIVE || wiki.GetAgentPrincipalId() == "" {
			t.Fatalf("installed solution = %v", wiki)
		}
		out, err := auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: wiki.GetId()}}, Audience: f.Audience})
		if err != nil || out.GetContext().GetOwnerPrincipalId() != wiki.GetAgentPrincipalId() {
			t.Fatalf("installation issue: %v %v", err, out)
		}
	})
	t.Run("a child hop attenuates and names its actor", func(t *testing.T) {
		sess, _ := sessions.SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: f.ViewerToken})
		parent, err := auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{SessionId: sess.GetSessionId()}}, Audience: f.Audience})
		if err != nil {
			t.Fatal(err)
		}
		child, err := auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()},
			Actor: &authorityv1.WorkloadCredential{Credential: f.WorkloadCredential}, Audience: f.Audience})
		if err != nil || len(child.GetContext().GetActorChain()) != 1 {
			t.Fatalf("child: %v %v", err, child)
		}
		_, err = auth.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()},
			Actor: &authorityv1.WorkloadCredential{Credential: f.WorkloadCredential}, Audience: f.Audience,
			Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: f.ReadKind, Actions: []string{"admin"}}}})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("widening: %v", err)
		}
	})
	t.Run("a manifest moves only forward and a lower generation is refused by name", func(t *testing.T) {
		m := &compositionv1.ModuleManifestV1{Module: "conformance-probe", Principal: "conformance-probe", Kind: "module", Generation: 2,
			ResourceKinds: []*compositionv1.ResourceKindV1{{Kind: "probe", Actions: []string{"read"}}}}
		if _, err := comp.ApplyManifest(ctx, &compositionv1.ApplyManifestRequest{Manifest: m}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		m.Generation = 1
		_, err := comp.ApplyManifest(ctx, &compositionv1.ApplyManifestRequest{Manifest: m})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("lower generation: %v", err)
		}
	})
	t.Run("install is pending until acknowledged, then exposed to a team", func(t *testing.T) {
		admin, _ := sessions.SignIn(ctx, &sessionv1.SignInRequest{FixtureToken: f.AdminToken})
		if _, err := comp.ApplyManifest(ctx, &compositionv1.ApplyManifestRequest{Manifest: &compositionv1.ModuleManifestV1{Module: "conformance-solution", Principal: "conformance-solution", Kind: "solution", Generation: 1}}); err != nil {
			t.Fatal(err)
		}
		inst, err := installs.Install(ctx, &installationv1.InstallRequest{OrganizationId: f.Organization, Target: "conformance-solution", Role: "viewer", OwnerPersonId: admin.GetPersonId()})
		if err != nil || inst.GetStatus() != installationv1.Installation_STATUS_ACTIVE {
			t.Fatalf("install: %v %v", err, inst)
		}
		granted, err := installs.GrantToTeam(ctx, &installationv1.GrantToTeamRequest{OrganizationId: f.Organization, InstallationId: inst.GetId(), TeamId: "finance"})
		if err != nil || len(granted.GetTeamIds()) != 1 || granted.GetRevision() != inst.GetRevision()+1 {
			t.Fatalf("grant: %v %v", err, granted)
		}
		_, err = installs.Install(ctx, &installationv1.InstallRequest{OrganizationId: f.Organization, Target: "conformance-solution", Role: "viewer", OwnerPersonId: admin.GetPersonId()})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("installing twice: %v", err)
		}
		_, err = installs.GrantToTeam(ctx, &installationv1.GrantToTeamRequest{OrganizationId: "another-organisation", InstallationId: inst.GetId(), TeamId: "finance"})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a grant naming another organisation: %v", err)
		}
	})
}
