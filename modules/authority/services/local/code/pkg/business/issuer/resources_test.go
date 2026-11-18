package issuer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

func issued(t *testing.T, k *testkit.Kit, fixtureToken string, scopes []*authorityv1.WorkScopeV1) string {
	t.Helper()
	out, err := k.Issuer.Issue(person(t, k, fixtureToken), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records", Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.GetToken()
}

func covered(t *testing.T, owned []authority.Grant) *resources.Matcher {
	t.Helper()
	var grants []resources.Grant
	for _, g := range owned {
		if g.Owner != "" {
			t.Fatalf("records checks no owner, and the grant names one: %+v", g)
		}
		grants = append(grants, g.Grant)
	}
	m, err := resources.Compile(grants)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The authority answers which collections a person reads at records, now,
// from the role they hold on its installation. A role names no resource: the
// page's user reads every collection, and a capability she narrowed to named
// ones covers exactly those.
func TestTheAuthorityAnswersWhichResourcesAContextCovers(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	named := issued(t, k, "fixture-maya", []*authorityv1.WorkScopeV1{
		{ResourceKind: "records.collection", Actions: []string{"read"}, ResourceIds: []string{"derived\x1fdirectory", "shared-finance"}},
	})
	maya, err := k.Issuer.ListResources(ctx, named, "records", "records.collection", "read")
	if err != nil {
		t.Fatal(err)
	}
	m := covered(t, maya)
	for id, want := range map[string]bool{"derived\x1fdirectory": true, "shared-finance": true, "finance": false, "shared-Finance": false} {
		if m.Matches(id) != want {
			t.Errorf("maya %q: want %v", id, want)
		}
	}
	if m.All() {
		t.Error("a capability narrowed to two collections covers every one")
	}
	for _, token := range []string{"fixture-maya", "fixture-remi"} {
		all, err := k.Issuer.ListResources(ctx, issued(t, k, token, nil), "records", "records.collection", "read")
		if err != nil || !covered(t, all).All() {
			t.Fatalf("%s, holding a role on records, reads every collection: %v %v", token, all, err)
		}
	}
	if _, err := k.Issuer.ListResources(ctx, named, "records", "records.collection", "admin"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an action the context does not hold: %v", err)
	}
	if _, err := k.Issuer.ListResources(ctx, named, "records", "records.nothing", "read"); err == nil {
		t.Fatal("a kind the module does not serve")
	}
}

// Asking for ids never widens: an ask naming an action the role lacks is
// refused even on a named id, and a capability narrowed to named resources
// covers exactly those.
func TestANarrowedContextCoversOnlyTheIDsItNames(t *testing.T) {
	k := testkit.New(t)
	_, err := k.Issuer.Issue(person(t, k, "fixture-maya"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "records",
		Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "records.collection", Actions: []string{"admin"}, ResourceIds: []string{"derived\x1fdirectory"}}},
	})
	if !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an ask naming an action the role lacks: %v", err)
	}
	token := issued(t, k, "fixture-maya", []*authorityv1.WorkScopeV1{
		{ResourceKind: "records.collection", Actions: []string{"read"}, ResourceIds: []string{"derived\x1fdirectory"}},
	})
	grants, err := k.Issuer.ListResources(context.Background(), token, "records", "records.collection", "read")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ID != "derived\x1fdirectory" {
		t.Fatalf("narrowed: %v", grants)
	}
}

var _ = basev0.WorkScopeV1{}
