package issuer_test

import (
	"context"
	"errors"
	"strings"
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
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", Scopes: scopes,
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
			t.Fatalf("an organisation grant names an owner: %+v", g)
		}
		grants = append(grants, g.Grant)
	}
	m, err := resources.Compile(grants)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The authority answers which collections a person reads from her roles, now.
// Maya reads by prefix and pattern, which a token cannot carry: she names the
// collections she acts on, and an ask naming none carries none of the kind.
func TestTheAuthorityAnswersWhichResourcesAContextCovers(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	named := issued(t, k, "fixture-maya", []*authorityv1.WorkScopeV1{
		{ResourceKind: "documents.collection", Actions: []string{"read"}, ResourceIds: []string{"derived\x1fdirectory", "shared-finance"}},
	})
	maya, err := k.Issuer.ListResources(ctx, named, "documents", "documents.collection", "read")
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
		t.Error("maya reads every collection")
	}
	if _, err := k.Issuer.ListResources(ctx, issued(t, k, "fixture-maya", nil), "documents", "documents.collection", "read"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an ask naming no collection carried the kind: %v", err)
	}
	remi, err := k.Issuer.ListResources(ctx, issued(t, k, "fixture-remi", nil), "documents", "documents.collection", "read")
	if err != nil || !covered(t, remi).All() {
		t.Fatalf("an editor reads every collection: %v %v", remi, err)
	}
	if _, err := k.Issuer.ListResources(ctx, named, "documents", "documents.collection", "admin"); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("an action the context does not hold: %v", err)
	}
	if _, err := k.Issuer.ListResources(ctx, named, "documents", "documents.nothing", "read"); err == nil {
		t.Fatal("a kind the module does not serve")
	}
}

// Asking for an id never widens: an ask naming one the owner's grants do not
// cover is refused, even beside one they do, and a capability narrowed to
// named resources covers exactly those.
func TestANarrowedContextCoversOnlyTheIDsItNamesThatTheOwnerHolds(t *testing.T) {
	k := testkit.New(t)
	_, err := k.Issuer.Issue(person(t, k, "fixture-maya"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
		Scopes: []*authorityv1.WorkScopeV1{{ResourceKind: "documents.collection", Actions: []string{"read"}, ResourceIds: []string{"derived\x1fdirectory", "secret"}}},
	})
	if !errors.Is(err, issuer.ErrRefused) || !strings.Contains(err.Error(), "widens") {
		t.Fatalf("an ask naming an id the owner does not hold: %v", err)
	}
	token := issued(t, k, "fixture-maya", []*authorityv1.WorkScopeV1{
		{ResourceKind: "documents.collection", Actions: []string{"read"}, ResourceIds: []string{"derived\x1fdirectory"}},
	})
	grants, err := k.Issuer.ListResources(context.Background(), token, "documents", "documents.collection", "read")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].ID != "derived\x1fdirectory" {
		t.Fatalf("narrowed: %v", grants)
	}
}

var _ = basev0.WorkScopeV1{}
