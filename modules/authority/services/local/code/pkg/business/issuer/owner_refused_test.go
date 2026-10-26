package issuer_test

import (
	"errors"
	"strings"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The wire carries resource_owner_id, and this authority cannot compare
// owners yet: an owner-selected ask is refused by name, never issued as the
// whole kind, and so is an owner-selected delegation.
func TestAnOwnerSelectedAskIsRefusedNeverWidened(t *testing.T) {
	k := testkit.New(t)
	owned := []*authorityv1.WorkScopeV1{{ResourceKind: "records.records", Actions: []string{"read"}, ResourceOwnerId: "principal-u"}}
	_, err := k.Issuer.Issue(person(t, k, "fixture-maya"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records", Scopes: owned})
	if !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "resource owner") {
		t.Fatalf("an owner-selected ask: %v", err)
	}
	_, err = k.Issuer.Delegate(person(t, k, "fixture-remi"), "org-directory",
		[]*base.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"read"}, ResourceOwnerId: "principal-u"}}, "owned")
	if !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "resource owner") {
		t.Fatalf("an owner-selected delegation: %v", err)
	}
}
