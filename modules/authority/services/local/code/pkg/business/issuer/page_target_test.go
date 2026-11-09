package issuer_test

import (
	"context"
	"testing"

	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// A page's call names its target: org-directory declares a binding to
// documents, so the person's capability there is the directory's hop over it,
// exactly the child its own workload would be issued, with org-directory the
// actor; with no page named, the person's own access answers.
func TestAPersonIssueNamingAPageGoesThroughItsTargetsBinding(t *testing.T) {
	k := testkit.New(t)
	viaPage, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", PageTarget: "org-directory"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory"})
	if err != nil {
		t.Fatal(err)
	}
	viaBackend, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: p.Token},
		Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}, Audience: "documents", OperationBindingId: "documents"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := actions(viaPage.Context, "documents"), actions(viaBackend.Context, "documents"); got != want || got == "" {
		t.Fatalf("through the page %q, through the backend %q", got, want)
	}
	chain := viaPage.Context.GetActorChain()
	if len(chain) == 0 || chain[len(chain)-1].GetPrincipalId() != "org-directory" {
		t.Fatalf("the page's target acts the hop: %v", chain)
	}
}
