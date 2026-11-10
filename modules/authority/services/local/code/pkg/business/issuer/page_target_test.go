package issuer_test

import (
	"context"
	"testing"

	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// A page's call names its target: org-directory declares a binding to
// records, so the person's capability there is the directory's hop over it,
// exactly the child its own workload would be issued, with org-directory the
// actor; with no page named, the person's own access answers.
func TestAPersonIssueNamingAPageGoesThroughItsTargetsBinding(t *testing.T) {
	k := testkit.New(t)
	viaPage, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records", PageTarget: "org-directory",
		Actor: &authorityv1.WorkloadCredential{Credential: k.EdgeCredential(t)}})
	if err != nil {
		t.Fatal(err)
	}
	// Only the module edge names a page: not a module, not a caller with none.
	for _, actor := range []*authorityv1.WorkloadCredential{nil, {Credential: k.Credential(t, "org-directory")}} {
		if _, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records", PageTarget: "org-directory", Actor: actor}); err == nil {
			t.Fatalf("a page named with actor %v was honoured", actor)
		}
	}
	p, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory"})
	if err != nil {
		t.Fatal(err)
	}
	viaBackend, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: p.Token},
		Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}, Audience: "records", OperationBindingId: "records"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := actions(viaPage.Context, "records.records"), actions(viaBackend.Context, "records.records"); got != want || got == "" {
		t.Fatalf("through the page %q, through the backend %q", got, want)
	}
	chain := viaPage.Context.GetActorChain()
	if len(chain) != 1 || chain[0].GetPrincipalId() != "org-directory" || chain[0].GetPrincipalKind() != "page" {
		t.Fatalf("the page's target acts the hop: %v", chain)
	}
}
