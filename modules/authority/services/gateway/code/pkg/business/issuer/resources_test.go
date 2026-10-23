package issuer_test

import (
	"context"
	"errors"
	"testing"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

func issued(t *testing.T, k *testkit.Kit, fixtureToken string, scopes []*authorityv1.WorkScopeV1) string {
	t.Helper()
	out, err := k.Issuer.Issue(person(t, k, fixtureToken), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.GetToken()
}

func covered(t *testing.T, grants []resources.Grant) *resources.Matcher {
	t.Helper()
	m, err := resources.Compile(grants)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The authority answers which collections a person reads from her roles, now;
// the token carries the kind alone.
func TestTheAuthorityAnswersWhichResourcesAContextCovers(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	maya, err := k.Issuer.ListResources(ctx, issued(t, k, "fixture-maya", nil), "documents", "documents.collection", "read")
	if err != nil {
		t.Fatal(err)
	}
	m := covered(t, maya)
	for id, want := range map[string]bool{"directory/2026": true, "shared-finance": true, "finance": false, "shared-Finance": false} {
		if m.Matches(id) != want {
			t.Errorf("maya %q: want %v", id, want)
		}
	}
	remi, err := k.Issuer.ListResources(ctx, issued(t, k, "fixture-remi", nil), "documents", "documents.collection", "read")
	if err != nil || !covered(t, remi).All() {
		t.Fatalf("an editor reads every collection: %v %v", remi, err)
	}
	if _, err := k.Issuer.ListResources(ctx, issued(t, k, "fixture-maya", nil), "documents", "documents.collection", "admin"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an action the context does not hold: %v", err)
	}
	if _, err := k.Issuer.ListResources(ctx, issued(t, k, "fixture-maya", nil), "documents", "documents.nothing", "read"); err == nil {
		t.Fatal("a kind the module does not serve")
	}
}

// A capability narrowed to named resources covers only those the owner's
// grants cover: asking for an id never widens.
func TestANarrowedContextCoversOnlyTheIDsItNamesThatTheOwnerHolds(t *testing.T) {
	k := testkit.New(t)
	token := issued(t, k, "fixture-maya", []*authorityv1.WorkScopeV1{
		{ResourceKind: "documents.collection", Actions: []string{"read"}, ResourceIds: []string{"directory/a", "secret"}},
	})
	grants, err := k.Issuer.ListResources(context.Background(), token, "documents", "documents.collection", "read")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ID != "directory/a" {
		t.Fatalf("narrowed: %v", grants)
	}
}

var _ = basev0.WorkScopeV1{}
