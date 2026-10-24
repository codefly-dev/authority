package issuer_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	artifactv1 "gateway/pkg/gen/host/artifact/v1"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// robin is a module whose authored artifacts people consent to: its intents
// kind is the policy, and the fixture's admin holds activate on it, its editor
// run. assistant is a module that hops to robin on a person's behalf.
func composeRobin(t *testing.T, k *testkit.Kit) {
	t.Helper()
	for _, m := range []state.Manifest{
		{Module: "robin", Principal: "robin", Kind: "module", Generation: 1,
			ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("robin.intents", "read", "run", "import", "configure", "activate"), testkit.Scope("robin.tasks", "execute", "read")},
			Bindings:      map[string]state.Binding{}},
		{Module: "assistant", Principal: "assistant", Kind: "module", Generation: 1,
			ResourceKinds: []*basev0.WorkScopeV1{testkit.Scope("assistant.task", "run")},
			Bindings: map[string]state.Binding{"robin": {ID: "robin", Audience: "robin",
				InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("robin.intents", "activate", "run")}}}},
	} {
		if _, err := k.State.ApplyManifest(m); err != nil {
			t.Fatal(err)
		}
	}
}

func personAt(t *testing.T, k *testkit.Kit, token, audience string) string {
	t.Helper()
	out, err := k.Issuer.Issue(person(t, k, token), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: audience,
	})
	if err != nil {
		t.Fatalf("%s at %s: %v", token, audience, err)
	}
	return out.GetToken()
}

func fieldNaturalist(revision int64) *artifactv1.Identity {
	return &artifactv1.Identity{Schema: "robin.configuration/v2", Source: "acme.robin", Subject: []byte(`{"name":"field-naturalist","instructions":"sha256:ab"}`),
		Contracts: []*artifactv1.Contract{{Kind: "profile", Name: "vertex/google/gemini-2.5-flash-lite", Digest: "sha256:01"}}, ExpectedRevision: revision}
}

func TestAPersonPresentApprovesAnArtifactAndARunReadsItBack(t *testing.T) {
	k := testkit.New(t)
	composeRobin(t, k)
	ctx := context.Background()
	robin := k.Credential(t, "robin")
	acmeRobin := state.InstallationID("acme", "robin")
	alex := personAt(t, k, "fixture-alex", "robin")

	approved, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: alex, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: fieldNaturalist(3)})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !strings.HasPrefix(approved.GetQualifiedName(), "host/approved-artifacts/") || !strings.HasPrefix(approved.GetDigest(), "sha256:") || len(approved.GetDigest()) != len("sha256:")+64 || approved.GetExpectedRevision() != 3 {
		t.Fatalf("approval = %v", approved)
	}
	// Approving again is the same consent, not a second one.
	again, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: alex, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: fieldNaturalist(3)})
	if err != nil || !proto.Equal(again, approved) {
		t.Fatalf("approving again: %v %v", again, err)
	}
	// Remi, an editor, runs it: she holds run, not activate.
	remi := personAt(t, k, "fixture-remi", "robin")
	run, err := k.Issuer.Artifact(ctx, "run", &artifactv1.ArtifactRequest{ParentToken: remi, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: fieldNaturalist(3)})
	if err != nil || !proto.Equal(run, approved) {
		t.Fatalf("run reads back: %v %v", run, err)
	}
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: remi, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: fieldNaturalist(3)}); !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "robin.intents:activate") {
		t.Fatalf("an editor approving: %v", err)
	}
	// A different artifact, or the same one for another installation, stands unapproved.
	other := fieldNaturalist(3)
	other.Subject = []byte(`{"name":"tool-assistant"}`)
	if _, err := k.Issuer.Artifact(ctx, "run", &artifactv1.ArtifactRequest{ParentToken: remi, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: other}); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("an unapproved artifact ran: %v", err)
	}
	// Revoked, for good.
	id := strings.TrimPrefix(approved.GetQualifiedName(), "host/approved-artifacts/")
	if _, err := k.Issuer.RevokeArtifact(ctx, &artifactv1.RevokeRequest{ParentToken: remi, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", ApprovalId: id}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an editor revoking: %v", err)
	}
	if _, err := k.Issuer.RevokeArtifact(ctx, &artifactv1.RevokeRequest{ParentToken: alex, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", ApprovalId: id}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "run", &artifactv1.ArtifactRequest{ParentToken: remi, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: fieldNaturalist(3)}); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("a revoked artifact ran: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: alex, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: fieldNaturalist(3)}); !errors.Is(err, state.ErrForbidden) || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("approving a revoked artifact again: %v", err)
	}
}

func TestConsentIsThePersonsOwnAtTheModuleAsking(t *testing.T) {
	k := testkit.New(t)
	composeRobin(t, k)
	ctx := context.Background()
	robin, documents, assistant := k.Credential(t, "robin"), k.Credential(t, "documents"), k.Credential(t, "assistant")
	acmeRobin := state.InstallationID("acme", "robin")
	identity := fieldNaturalist(1)

	// A context addressed to another module is not consent at robin.
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: personAt(t, k, "fixture-alex", "documents"), ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: identity}); !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "addressed to documents") {
		t.Fatalf("another audience: %v", err)
	}
	// Nor is robin's context presented by another module.
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: personAt(t, k, "fixture-alex", "robin"), ActorCredential: documents, InstallationId: acmeRobin, Policy: "robin.intents", Identity: identity}); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("another module asking: %v", err)
	}
	// A module acting for the person cannot consent for them, however much it holds; it may run.
	dev := personAt(t, k, "fixture-dev", "assistant")
	child, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: dev}, Actor: &authorityv1.WorkloadCredential{Credential: assistant}, OperationBindingId: "robin",
	})
	if err != nil {
		t.Fatalf("child: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: child.GetToken(), ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: identity}); !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "person present") {
		t.Fatalf("a delegated consent: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: dev, ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: identity}); !errors.Is(err, issuer.ErrRefused) {
		// dev's token is addressed to assistant, not robin.
		t.Fatalf("dev at assistant: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "activate", &artifactv1.ArtifactRequest{ParentToken: personAt(t, k, "fixture-dev", "robin"), ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: identity}); err != nil {
		t.Fatalf("dev in person: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "run", &artifactv1.ArtifactRequest{ParentToken: child.GetToken(), ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.intents", Identity: identity}); err != nil {
		t.Fatalf("a delegated run: %v", err)
	}
	// Another organisation's installation, and a policy nobody holds.
	if _, err := k.Issuer.Artifact(ctx, "run", &artifactv1.ArtifactRequest{ParentToken: personAt(t, k, "fixture-dev", "robin"), ActorCredential: robin, InstallationId: state.InstallationID("globex", "robin"), Policy: "robin.intents", Identity: identity}); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("globex's installation: %v", err)
	}
	if _, err := k.Issuer.Artifact(ctx, "run", &artifactv1.ArtifactRequest{ParentToken: personAt(t, k, "fixture-remi", "robin"), ActorCredential: robin, InstallationId: acmeRobin, Policy: "robin.tasks", Identity: identity}); !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "robin.tasks:run") {
		t.Fatalf("a policy kind without the action: %v", err)
	}
}

func TestAnInstallationNamesItsNamespace(t *testing.T) {
	k := testkit.New(t)
	composeRobin(t, k)
	inst, ok := k.State.Installation(state.InstallationID("acme", "robin"))
	if !ok || inst.Namespace() != "acme.robin" {
		t.Fatalf("namespace = %q (%v)", inst.Namespace(), ok)
	}
}
