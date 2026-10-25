package issuer_test

// The primer's section 4, one scenario, one hop at a time, run against the mini
// gateway with the same cast: Acme, Maya on Finance, Rémi the engineer, the
// wiki, documents, model, runtime, records and the org-directory page. Each
// step asserts what the primer says the token carries and what refuses today.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/codefly-dev/core/workcontext"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

func TestTheScenarioOneHopAtATime(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	documents := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")}
	var maya state.Session
	var asMaya context.Context
	var mayaAtDocuments string

	t.Run("1 Maya signs in", func(t *testing.T) {
		var err error
		maya, err = k.State.SignIn("fixture-maya")
		if err != nil || maya.Organization != "acme" || maya.Teams[0] != "finance" {
			t.Fatalf("Maya's session: %v %+v", err, maya)
		}
		asMaya = issuer.WithSession(ctx, maya.ID) // the bearer every call of hers carries
		// Her session says who she is, not what she may do in documents.
		if len(maya.Roles) != 1 || maya.Roles[0] != "viewer" {
			t.Fatalf("roles = %v", maya.Roles)
		}
	})

	t.Run("2 Maya sees the wiki in her navigation", func(t *testing.T) {
		nav := k.State.Entitled(maya.Person)
		if len(nav) != 1 || nav[0].Target != "wiki" {
			t.Fatalf("Maya's navigation = %+v", nav)
		}
		// Rémi on engineering sees it too: the installation reaches both teams.
		if nav := k.State.Entitled("remi"); len(nav) != 1 || nav[0].Target != "wiki" {
			t.Fatalf("Rémi's navigation = %+v", nav)
		}
	})

	t.Run("3 the wiki reads a page body from documents on Maya's behalf", func(t *testing.T) {
		out, err := k.Issuer.Issue(asMaya, &authorityv1.IssueRequest{
			As:       &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}},
			Audience: "documents", Scopes: scopes(testkit.Scope("documents", "read")),
		})
		if err != nil {
			t.Fatal(err)
		}
		wc := out.GetContext()
		// owner = actor = Maya; audience documents; scopes = roles ∩ ceiling; sealed to documents at Acme.
		if wc.GetOwnerPrincipalId() != "maya" || len(wc.GetActorChain()) != 0 || wc.GetAudience() != "documents" ||
			wc.GetSeal().GetInstallationId() != state.InstallationID("acme", "documents") || strings.Join(wc.GetAuthorityScopes()[0].GetActions(), ",") != "read" {
			t.Fatalf("step 3 token = %v", wc)
		}
		if _, err := k.Issuer.Check(ctx, out.GetToken(), "documents", ""); err != nil {
			t.Fatalf("documents checks it: %v", err)
		}
		mayaAtDocuments = out.GetToken()
		// Refuses today: a role the solution cannot declare. Here the viewer role
		// is declared in the fixture and write is refused by name.
		_, err = k.Issuer.Issue(asMaya, &authorityv1.IssueRequest{
			As:       &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}},
			Audience: "documents", Scopes: scopes(testkit.Scope("documents", "write")),
		})
		if !errors.Is(err, issuer.ErrRefused) {
			t.Fatalf("a viewer writing: %v", err)
		}
	})

	t.Run("4 documents embeds the page through the model gateway, for itself", func(t *testing.T) {
		out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Workload{Workload: documents}, Audience: "model", OrganizationId: "acme", OperationBindingId: "model",
		})
		if err != nil {
			t.Fatal(err)
		}
		wc := out.GetContext()
		if wc.GetOwnerPrincipalId() != "documents" || wc.GetOwnerPrincipalKind() != "service" || wc.GetAudience() != "model" ||
			wc.GetOperationBinding().GetBindingId() != "acme/documents/model" || wc.GetSeal().GetInstallationId() != state.InstallationID("acme", "documents") {
			t.Fatalf("step 4 token = %v", wc)
		}
		if _, err := k.Issuer.Check(ctx, out.GetToken(), "model", ""); err != nil {
			t.Fatalf("model checks it: %v", err)
		}
		// Refuses today, the audience: the composition typed modelservice in a second key.
		_, err = k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Workload{Workload: documents}, Audience: "modelservice", OrganizationId: "acme", OperationBindingId: "model",
		})
		if !errors.Is(err, state.ErrUnknown) || !strings.Contains(err.Error(), `"modelservice" is not composed`) {
			t.Fatalf("the audience typo: %v", err)
		}
		// Refuses today, all or nothing: the envelope forgot runtime-admission and
		// documents lost its whole entry. Here documents keeps both bindings.
		if _, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Workload{Workload: documents}, Audience: "runtime", OrganizationId: "acme", OperationBindingId: "runtime-admission",
		}); err != nil {
			t.Fatalf("the second binding: %v", err)
		}
	})

	t.Run("5 Maya starts a sync; documents fans it out through the runtime", func(t *testing.T) {
		// A per-call child: owner Maya, actor documents, audience runtime, scopes ⊆ the parent's, short.
		child, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_ParentToken{ParentToken: mayaAtDocuments}, Actor: documents,
			Audience: "runtime", OperationBindingId: "runtime-admission", TtlSeconds: 60,
		})
		if err != nil {
			t.Fatal(err)
		}
		wc := child.GetContext()
		if wc.GetOwnerPrincipalId() != "maya" || len(wc.GetActorChain()) != 1 || wc.GetActorChain()[0].GetPrincipalId() != "documents" ||
			wc.GetAudience() != "runtime" || wc.GetExpiresAtUnix()-k.Now.Unix() < 60 || wc.GetExpiresAtUnix()-k.Now.Unix() > 62 {
			t.Fatalf("step 5 child = %v", wc)
		}
		if _, err := k.Issuer.Check(ctx, child.GetToken(), "runtime", ""); err != nil {
			t.Fatalf("the runtime checks the child: %v", err)
		}
		// Nothing widened: the child cannot carry more than Maya's read.
		_, err = k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_ParentToken{ParentToken: mayaAtDocuments}, Actor: documents,
			Audience: "runtime", Scopes: scopes(testkit.Scope("documents", "write")),
		})
		if !errors.Is(err, issuer.ErrRefused) {
			t.Fatalf("widening through the runtime: %v", err)
		}
	})

	t.Run("6 overnight, the wiki reconciles, as itself", func(t *testing.T) {
		out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: state.InstallationID("acme", "wiki")}}, Audience: "wiki",
		})
		if err != nil {
			t.Fatal(err)
		}
		wc := out.GetContext()
		// owner = actor = the wiki at Acme; scopes = what Acme consented to at install (viewer) ∩ the solution's own ceiling. No downstream grant is implied.
		if wc.GetOwnerPrincipalId() != state.InstallationID("acme", "wiki")+"/agent" || wc.GetOwnerAgentId() != "wiki" || wc.GetSeal().GetInstallationId() != state.InstallationID("acme", "wiki") ||
			strings.Join(wc.GetAuthorityScopes()[0].GetActions(), ",") != "read" {
			t.Fatalf("step 6 token = %v", wc)
		}
		// Acme's administrator uninstalls the wiki at 10:00; the 09:58 token is refused at 10:00:01.
		if err := k.State.Revoke(state.InstallationID("acme", "wiki")); err != nil {
			t.Fatal(err)
		}
		if _, err := k.Issuer.Check(ctx, out.GetToken(), "wiki", ""); err == nil {
			t.Fatal("an uninstalled wiki still acted")
		}
	})

	t.Run("7 Maya opens a module page that reads records", func(t *testing.T) {
		// Today a module page has no path to a records-audience token. Here the
		// page is a module, Maya holds records read through her role, and the
		// page asks for Maya at records: the module-for-a-person shape.
		out, err := k.Issuer.Issue(asMaya, &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records",
		})
		if err != nil {
			t.Fatal(err)
		}
		wc := out.GetContext()
		kinds := map[string]string{}
		for _, sc := range wc.GetAuthorityScopes() {
			kinds[sc.GetResourceKind()] = strings.Join(sc.GetActions(), ",")
		}
		if kinds["records.records"] != "read" || kinds["records.types"] != "read" || wc.GetSeal().GetInstallationId() != state.InstallationID("acme", "records") {
			t.Fatalf("step 7 token = %v", wc)
		}
		// Rémi, an editor, is also issued write on records; the UI follows the token.
		remi, _ := k.State.SignIn("fixture-remi")
		out, err = k.Issuer.Issue(issuer.WithSession(ctx, remi.ID), &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records",
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, sc := range out.GetContext().GetAuthorityScopes() {
			if sc.GetResourceKind() == "records.records" && strings.Join(sc.GetActions(), ",") != "read,write" {
				t.Fatalf("Rémi at records = %v", sc)
			}
		}
	})

	t.Run("8 Rémi runs all of this on a laptop", func(t *testing.T) {
		// Everything above ran with no accounts service, no store, no envelope, no
		// anchor file: one launcher key, one fixture, one issuer. The only thing a
		// laptop and a cell share is the code that issued and checked.
		keys := k.Issuer.Keys()
		if keys.GetIssuer() == "" || len(keys.GetKeys()) != 1 {
			t.Fatalf("keys = %v", keys)
		}
		if _, err := k.State.VerifyWorkload(ctx, documents.GetCredential()); err != nil {
			t.Fatalf("the launcher's word for documents: %v", err)
		}
		if _, err := k.Issuer.Check(ctx, workcontext.FixtureForeignToken(), "documents", ""); err == nil {
			t.Fatal("a token that is not ours verified")
		}
	})
}
