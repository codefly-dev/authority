package issuer_test

import (
	"context"
	"errors"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

func installationManifest(name, role string, generation uint64, actions ...string) state.Manifest {
	kind := name + ".item"
	return state.Manifest{Module: name, Principal: name, Kind: "solution", Generation: generation,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope(kind, "read", "write")},
		Roles:         map[string][]*basev0.WorkScopeV1{state.InstallerRole: {testkit.Scope(kind, "read", "write")}, role: {testkit.Scope(kind, actions...)}},
		Bindings:      map[string]state.Binding{"self": {ID: "self", Audience: name, InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope(kind, "read", "write")}}}}
}

func TestInstallationRoleComesFromItsSolutionNotTheOrganization(t *testing.T) {
	for _, role := range []string{"viewer", "task_operator"} {
		t.Run(role, func(t *testing.T) {
			k := testkit.New(t)
			ctx := context.Background()
			for _, target := range []struct{ name, action string }{{"surface-a", "read"}, {"surface-b", "write"}} {
				if _, err := k.State.ApplyManifest(installationManifest(target.name, role, 1, target.action)); err != nil {
					t.Fatal(err)
				}
				inst, err := k.State.Install(ctx, "acme", target.name, role, "alex")
				if err != nil {
					t.Fatal(err)
				}
				request := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: inst.ID}}, Audience: target.name}
				out, err := k.Issuer.Issue(ctx, request)
				if err != nil {
					t.Fatalf("declared solution role cannot issue: %v", err)
				}
				held := out.GetContext().GetAuthorityScopes()
				if len(held) != 1 || held[0].GetResourceKind() != target.name+".item" || len(held[0].GetActions()) != 1 || held[0].GetActions()[0] != target.action {
					t.Fatalf("wrong role source: %v", held)
				}
				if _, err := k.Issuer.Check(ctx, out.GetToken(), target.name, ""); err != nil {
					t.Fatal(err)
				}
				request.Audience = "documents"
				if _, err := k.Issuer.Issue(ctx, request); !errors.Is(err, issuer.ErrRefused) {
					t.Fatalf("organisation role supplied unrelated Documents authority: %v", err)
				}
			}
		})
	}
}

func TestSolutionRoleNarrowingRevokesExistingRootsAndChildren(t *testing.T) {
	for _, remove := range []bool{false, true} {
		name := "narrow"
		if remove {
			name = "remove"
		}
		t.Run(name, func(t *testing.T) {
			k := testkit.New(t)
			ctx := context.Background()
			manifest := installationManifest("conformance-solution", "task_operator", 1, "read", "write")
			if _, err := k.State.ApplyManifest(manifest); err != nil {
				t.Fatal(err)
			}
			inst, err := k.State.Install(ctx, "acme", manifest.Module, "task_operator", "alex")
			if err != nil {
				t.Fatal(err)
			}
			request := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: inst.ID}}, Audience: manifest.Principal, Scopes: scopes(testkit.Scope("conformance-solution.item", "write"))}
			root, err := k.Issuer.Issue(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			child, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.GetToken()}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, manifest.Module)}, Audience: manifest.Principal, OperationBindingId: "self", Scopes: request.Scopes})
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{root.GetToken(), child.GetToken()} {
				if _, err := k.Issuer.Check(ctx, token, manifest.Principal, ""); err != nil {
					t.Fatalf("before narrowing: %v", err)
				}
			}
			other, err := k.Issuer.Issue(person(t, k, "fixture-zoe"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"})
			if err != nil {
				t.Fatal(err)
			}
			next := installationManifest("conformance-solution", "task_operator", 2, "read")
			if remove {
				delete(next.Roles, "task_operator")
			}
			if _, err := k.State.ApplyManifest(next); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{root.GetToken(), child.GetToken()} {
				if _, err := k.Issuer.Check(ctx, token, manifest.Principal, ""); !errors.Is(err, workcontext.ErrRevoked) {
					t.Fatalf("old role capability after narrowing: %v", err)
				}
			}
			if _, err := k.Issuer.Issue(ctx, request); err == nil {
				t.Fatal("fresh issuance recovered removed write")
			}
			request.Scopes = scopes(testkit.Scope("conformance-solution.item", "read"))
			if _, err := k.Issuer.Issue(ctx, request); (err == nil) == remove {
				t.Fatalf("fresh read after role change remove=%v: %v", remove, err)
			}
			if _, err := k.Issuer.Check(ctx, other.GetToken(), "documents", ""); err != nil {
				t.Fatalf("unrelated organization revoked: %v", err)
			}
		})
	}
}

func TestInstallerNarrowingRevokesTheOwnerButRoleExpansionKeepsExistingAuthority(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	m := installationManifest("conformance-solution", "viewer", 1, "read")
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	inst, err := k.State.Install(ctx, "acme", m.Module, "viewer", "alex")
	if err != nil {
		t.Fatal(err)
	}
	agent, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: inst.ID}}, Audience: m.Principal})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := k.Issuer.Issue(person(t, k, "fixture-alex"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: m.Principal, Scopes: scopes(testkit.Scope(m.Module+".item", "write"))})
	if err != nil {
		t.Fatal(err)
	}
	// Expanding the installed viewer role leaves already-issued narrow grants valid.
	next := installationManifest(m.Module, "viewer", 2, "read", "write")
	if _, err := k.State.ApplyManifest(next); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, agent.GetToken(), m.Principal, ""); err != nil {
		t.Fatalf("expansion invalidated old scope: %v", err)
	}
	// The owner's installer role is independent of that selected viewer role.
	next = installationManifest(m.Module, "viewer", 3, "read", "write")
	next.Roles[state.InstallerRole] = []*basev0.WorkScopeV1{testkit.Scope(m.Module+".item", "read")}
	if _, err := k.State.ApplyManifest(next); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Issuer.Check(ctx, owner.GetToken(), m.Principal, ""); !errors.Is(err, workcontext.ErrRevoked) {
		t.Fatalf("installer lost write but old token still works: %v", err)
	}
}
