package issuer_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

func actions(wc *authorityv1.WorkContextV1, kind string) string {
	for _, sc := range effectiveScopes(wc) {
		if sc.GetResourceKind() == kind {
			return strings.Join(sc.GetActions(), ",")
		}
	}
	return ""
}

// A lookup carries only what the binding may read back: Rémi may write
// documents through the page's binding, and a lookup through it may only read.
func TestALookupCarriesOnlyTheBindingsLookupScopes(t *testing.T) {
	k := testkit.New(t)
	remi := person(t, k, "fixture-remi")
	parent, err := k.Issuer.Issue(remi, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory"})
	if err != nil {
		t.Fatal(err)
	}
	hop := func(operation string) (*authorityv1.IssueResponse, error) {
		return k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.GetToken()}, Audience: "documents",
			Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")}, OperationBindingId: "documents", Operation: operation,
		})
	}
	invoke, err := hop("")
	if err != nil || actions(invoke.GetContext(), "documents") != "read,write" {
		t.Fatalf("invoke: %v %v", invoke.GetContext().GetAuthorityScopes(), err)
	}
	lookup, err := hop("lookup")
	if err != nil || actions(lookup.GetContext(), "documents") != "read" {
		t.Fatalf("lookup: %v %v", lookup.GetContext().GetAuthorityScopes(), err)
	}
	if _, err := hop("delete"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an operation the binding has not: %v", err)
	}
}

// A person grants the page the right to write documents for them; the page
// issues from the delegation with no live token of theirs, as them, until
// they revoke it.
func TestADelegationIssuesAsItsGrantorUntilRevoked(t *testing.T) {
	k := testkit.New(t)
	remi := person(t, k, "fixture-remi")
	write := []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}}}
	d, err := k.Issuer.Delegate(remi, "org-directory", issuer.FromWire(write), "a connected spreadsheet")
	if err != nil {
		t.Fatal(err)
	}
	issue := func(module string) (*authorityv1.IssueResponse, error) {
		return k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
			As: &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}}, Audience: "documents",
			Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, module)}, OperationBindingId: "documents",
		})
	}
	out, err := issue("org-directory")
	if err != nil {
		t.Fatal(err)
	}
	wc := out.GetContext()
	chain := wc.GetActorChain()
	if wc.GetOwnerPrincipalId() != "remi" || wc.GetOwnerPrincipalKind() != "human" || len(chain) != 1 ||
		chain[0].GetPrincipalId() != "org-directory" || chain[0].GetDelegationId() != d.ID || actions(wc, "documents") != "write" {
		t.Fatalf("issued: owner %s %s, chain %v, scopes %v", wc.GetOwnerPrincipalId(), wc.GetOwnerPrincipalKind(), chain, wc.GetAuthorityScopes())
	}
	if _, err := k.Issuer.Check(context.Background(), out.GetToken(), "documents", ""); err != nil {
		t.Fatalf("the issued capability checks at its audience: %v", err)
	}
	if _, err := issue("documents"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("another module presents the delegation: %v", err)
	}
	// Someone else, neither its grantor nor an administrator, learns nothing of it.
	if _, err := k.Issuer.RevokeDelegation(person(t, k, "fixture-maya"), d.ID); !errors.Is(err, state.ErrUnknown) {
		t.Fatalf("someone else revokes it: %v", err)
	}
	if _, err := k.Issuer.RevokeDelegation(remi, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := issue("org-directory"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a revoked delegation issues: %v", err)
	}
}

func TestNobodyDelegatesWhatTheyDoNotHold(t *testing.T) {
	k := testkit.New(t)
	write := []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}}}
	if _, err := k.Issuer.Delegate(person(t, k, "fixture-maya"), "org-directory", issuer.FromWire(write), "x"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a viewer delegates write: %v", err)
	}
	if _, err := k.Issuer.Delegate(context.Background(), "org-directory", issuer.FromWire(write), "x"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("a delegation with no signed-in person: %v", err)
	}
}
