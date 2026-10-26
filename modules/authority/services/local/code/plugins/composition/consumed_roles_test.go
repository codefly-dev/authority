package composition

import (
	"context"
	"errors"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	compositionv1 "gateway/pkg/gen/host/composition/v1"
	"github.com/codefly-dev/core/solutionhost"
	"github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func consumedRoleDocument(consumed ...*authorityv1.WorkScopeV1) *compositionv1.AuthorityManifestV1 {
	own := scope("conformance.page", "read")
	return &compositionv1.AuthorityManifestV1{
		ScopeCeilings: []*authorityv1.WorkScopeV1{own},
		Roles: []*compositionv1.RoleV1{
			{Name: state.InstallerRole, Scopes: []*authorityv1.WorkScopeV1{own}},
			{Name: "operator", Scopes: append([]*authorityv1.WorkScopeV1{own}, consumed...)},
		},
	}
}

func consumedRoleBinding(binding solutionhost.AuthorityBinding) func(*solutionhost.ModuleManifest) {
	return func(m *solutionhost.ModuleManifest) {
		m.Authority.Bindings = []solutionhost.AuthorityBinding{binding}
		m.Workloads = []solutionhost.Workload{{Service: "conformance-solution", Container: "conformance-solution"}}
	}
}

func TestSignedSolutionRolesMayGrantOnlyDeclaredPersonOperations(t *testing.T) {
	for _, tc := range []struct {
		name       string
		operations map[string][]string
		grant      *authorityv1.WorkScopeV1
		allowed    bool
	}{
		{"invoke", map[string][]string{"invoke": {"documents:write"}}, scope("documents", "write"), true},
		{"lookup with headless", map[string][]string{"headless": {"documents:read", "documents:write"}, "lookup": {"documents:read"}}, scope("documents", "read"), true},
		{"headless alone", map[string][]string{"headless": {"documents:write"}}, scope("documents", "write"), false},
		{"undeclared kind", map[string][]string{"invoke": {"documents:read"}}, scope("records.records", "read"), false},
		{"undeclared action", map[string][]string{"invoke": {"documents:read"}}, scope("documents", "write"), false},
		{"lookup cannot borrow headless write", map[string][]string{"headless": {"documents:read", "documents:write"}, "lookup": {"documents:read"}}, scope("documents", "write"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, k := verifying(t)
			binding := solutionhost.AuthorityBinding{ID: "documents", Audience: "documents", Operations: tc.operations}
			req := carrier(t, k, "conformance-solution", solutionhost.KindSolution, 1, []string{"conformance.page"}, consumedRoleDocument(tc.grant), consumedRoleBinding(binding))
			_, err := p.ApplyManifest(context.Background(), req)
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("invalid role admitted: %v", err)
				}
				if _, err := k.State.ModuleByPrincipal("conformance-solution"); !errors.Is(err, state.ErrUnknown) {
					t.Fatalf("refused delivery changed state: %v", err)
				}
			}
		})
	}
}

// Exercise the signed delivery, real installation and issuer together. A
// consumed role grant is usable by that installation; it neither changes the
// solution's served vocabulary nor the person's independent organisation roles.
func TestConsumedInstallationRoleIssuesAndRevokesAcrossAudiences(t *testing.T) {
	for _, change := range []string{"role narrowing", "binding and role narrowing", "role removal"} {
		t.Run(change, func(t *testing.T) {
			p, k := verifying(t)
			ctx := context.Background()
			binding := solutionhost.AuthorityBinding{ID: "documents", Audience: "documents", Operations: map[string][]string{"invoke": {"documents:read", "documents:write"}, "lookup": {"documents:read"}}}
			doc := consumedRoleDocument(scope("documents", "write"))
			deliver := func(generation uint64) {
				t.Helper()
				if _, err := p.ApplyManifest(ctx, carrier(t, k, "conformance-solution", solutionhost.KindSolution, generation, []string{"conformance.page"}, doc, consumedRoleBinding(binding))); err != nil {
					t.Fatal(err)
				}
			}
			deliver(1)
			inst, err := k.State.Install(ctx, "acme", "conformance-solution", "operator", "alex")
			if err != nil {
				t.Fatal(err)
			}
			if err := k.State.GrantRole(domain.RoleGrant{InstallationID: inst.ID, Role: "operator", TeamID: "finance"}); err != nil {
				t.Fatal(err)
			}
			if got := held(t, k, "maya", "conformance-solution"); got != "conformance.page:read" {
				t.Fatalf("consumed permission became served: %s", got)
			}
			if got := held(t, k, "maya", "documents"); got != "documents:read documents.collection:read" {
				t.Fatalf("installation changed organisation grants: %s", got)
			}
			// The same delivered role supplies a person's consumed authority;
			// Maya's independent organisation role remains read-only above.
			session, err := k.State.SignIn("fixture-maya")
			if err != nil {
				t.Fatal(err)
			}
			personContext := issuer.WithSession(ctx, session.ID)
			personRequest := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "conformance-solution", OperationBindingId: "documents", Scopes: []*authorityv1.WorkScopeV1{scope("documents", "write")}}
			personRoot, err := k.Issuer.Issue(personContext, personRequest)
			if err != nil {
				t.Fatal(err)
			}
			personChild, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: personRoot.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "conformance-solution")}, Audience: "documents", OperationBindingId: "documents", Scopes: []*authorityv1.WorkScopeV1{scope("documents", "write")}})
			if err != nil {
				t.Fatal(err)
			}
			grants, err := k.Issuer.ListResources(ctx, personChild.Token, "documents", "documents", "write")
			if err != nil || len(grants) != 1 || !grants[0].All {
				t.Fatalf("delivered person role lost its resource grant: %v %v", grants, err)
			}
			request := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: inst.ID}}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, inst.Target)}, Audience: "conformance-solution"}
			root, err := k.Issuer.Issue(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			request.Audience = "documents"
			direct, err := k.Issuer.Issue(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(direct.Context.AuthorityScopes[0], scope("documents", "write")) || len(direct.Context.AuthorityScopes) != 1 {
				t.Fatalf("wrong consumed grant: %v", direct.Context.AuthorityScopes)
			}
			credential := k.Credential(t, "conformance-solution")
			childRequest := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: credential}, Audience: "documents", OperationBindingId: "documents", Scopes: []*authorityv1.WorkScopeV1{scope("documents", "write")}}
			child, err := k.Issuer.Issue(ctx, childRequest)
			if err != nil {
				t.Fatal(err)
			}
			// A binding permits read, but this installation's role does not grant it.
			request.Scopes = []*authorityv1.WorkScopeV1{scope("documents", "read")}
			if _, err := k.Issuer.Issue(ctx, request); !errors.Is(err, issuer.ErrRefused) {
				t.Fatalf("binding became a grant: %v", err)
			}
			childRequest.Operation = "lookup"
			if _, err := k.Issuer.Issue(ctx, childRequest); !errors.Is(err, issuer.ErrRefused) {
				t.Fatalf("lookup recovered write: %v", err)
			}
			for _, issued := range []*authorityv1.IssueResponse{root, direct, child, personRoot, personChild} {
				if _, err := k.Issuer.Check(ctx, issued.Token, issued.Context.Audience, ""); err != nil {
					t.Fatal(err)
				}
			}
			doc = consumedRoleDocument(scope("documents", "read"))
			if change == "binding and role narrowing" {
				binding.Operations["invoke"] = []string{"documents:read"}
			}
			if change == "role removal" {
				doc.Roles = doc.Roles[:1]
			}
			deliver(2)
			for _, issued := range []*authorityv1.IssueResponse{root, direct, child, personRoot, personChild} {
				if _, err := k.Issuer.Check(ctx, issued.Token, issued.Context.Audience, ""); !errors.Is(err, workcontext.ErrRevoked) {
					t.Fatalf("old consumed role survived %s: %v", change, err)
				}
			}
			request.Scopes = []*authorityv1.WorkScopeV1{scope("documents", "write")}
			if _, err := k.Issuer.Issue(ctx, request); err == nil {
				t.Fatal("fresh issuance recovered write")
			}
			if _, err := k.Issuer.Issue(personContext, personRequest); err == nil {
				t.Fatal("fresh person issuance recovered removed solution write")
			}
		})
	}
}

