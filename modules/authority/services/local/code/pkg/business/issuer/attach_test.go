package issuer_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A kind two composed modules declare has no one module trusted to say what
// was created, so neither attaches anything of it.
func TestAttachmentNeedsTheKindsOneServingModule(t *testing.T) {
	k := testkit.New(t)
	decoy := state.Manifest{Module: "robin", Principal: "robin", Kind: "module", Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("documents.collection", "read")}}
	if _, err := k.State.ApplyManifest(decoy); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"documents", "robin"} {
		_, err := k.Issuer.AttachResource(t.Context(), "not-read", k.Credential(t, module), "documents.collection", "c1")
		if !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "one serving module") {
			t.Fatalf("%s: %v", module, err)
		}
	}
}

// ownKindSolution installs a solution serving its own kind: its installer
// creates items, its viewer reads the items and administers collections at
// documents, and reads the collections its installation owns.
func ownKindSolution(t *testing.T, k *testkit.Kit) string {
	t.Helper()
	m := state.Manifest{Module: "proposals", Principal: "proposals", Kind: "solution", Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "create", "read")},
		Bindings: map[string]state.Binding{"documents": {ID: "documents", Audience: "documents",
			InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("documents.collection", "read", "admin")}}},
		Roles: map[string][]*basev0.WorkScopeV1{
			state.InstallerRole: {testkit.Scope("proposals.item", "create")},
			"viewer":            {testkit.Scope("documents.collection", "admin")},
		},
		OwnedRoles: map[string][]*basev0.WorkScopeV1{
			state.InstallerRole: {testkit.Scope("proposals.item", "read")},
			"viewer":            {testkit.Scope("proposals.item", "read"), testkit.Scope("documents.collection", "read")},
		}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	inst, err := k.State.Install(context.Background(), "acme", "proposals", "viewer", "alex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.GrantToTeam(context.Background(), "acme", inst.ID, "finance"); err != nil {
		t.Fatal(err)
	}
	return inst.ID
}

func ownedRead(scopes []*basev0.WorkScopeV1, kind string) []string {
	for _, scope := range scopes {
		if scope.GetResourceKind() == kind && slices.Contains(scope.GetActions(), "read") {
			return scope.GetResourceIds()
		}
	}
	return nil
}

// An installed solution serving its own kind attaches through a person's
// capability addressed to it: the installation is the one its seal names.
func TestASolutionAttachesItsOwnKindThroughAPersonsCapability(t *testing.T) {
	k := testkit.New(t)
	id := ownKindSolution(t, k)
	created, err := k.Issuer.Issue(person(t, k, "fixture-alex"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "proposals"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Issuer.AttachResource(t.Context(), created.GetToken(), k.Credential(t, "proposals"), "proposals.item", "p1")
	if err != nil || got != id {
		t.Fatalf("attached to %q (%v), want %s", got, err, id)
	}
	held, err := k.State.PersonSolutionScopes("maya", "proposals")
	if err != nil {
		t.Fatal(err)
	}
	if ids := ownedRead(held, "proposals.item"); !slices.Equal(ids, []string{"p1"}) {
		t.Fatalf("the viewer reads %v, want [p1]", ids)
	}
}

// An installation acting for itself attaches what it administers into itself.
func TestAnInstallationAgentAttachesIntoItsInstallation(t *testing.T) {
	k := testkit.New(t)
	id := ownKindSolution(t, k)
	agent, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
		As:    &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: id}},
		Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "proposals")}, Audience: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	if agent.GetContext().GetOwnerPrincipalKind() != "agent" {
		t.Fatalf("owner kind %q", agent.GetContext().GetOwnerPrincipalKind())
	}
	got, err := k.Issuer.AttachResource(t.Context(), agent.GetToken(), k.Credential(t, "documents"), "documents.collection", "c-agent")
	if err != nil || got != id {
		t.Fatalf("attached to %q (%v), want %s", got, err, id)
	}
	held, err := k.State.PersonSolutionScopes("maya", "proposals")
	if err != nil {
		t.Fatal(err)
	}
	if ids := ownedRead(held, "documents.collection"); !slices.Equal(ids, []string{"c-agent"}) {
		t.Fatalf("the viewer reads %v, want [c-agent]", ids)
	}
}
