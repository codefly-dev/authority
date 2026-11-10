package issuer_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
)

// One person, several roles, one session per view: the fixture's owner of the
// wiki holds installer and viewer there (his teams are granted viewer), so
// there is something to select. Acting as viewer, Alex holds exactly what Rémi,
// a real viewer through his team, holds at the wiki, and not the publish his own
// session holds. The wiki rows of the matrix for a viewer are Rémi's; the
// organization-role rows keep Maya, because a role view narrows installation
// roles and organization roles are not selectable until they are read through
// the core too (RBAC-4b).
func TestAlexActingAsViewerHoldsWhatARealViewerHoldsAtTheWiki(t *testing.T) {
	k := testkit.New(t)
	wikiScopes := func(ctx context.Context) []string {
		t.Helper()
		out, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "wiki"})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, sc := range out.GetContext().GetAuthorityScopes() {
			got = append(got, sc.GetResourceKind()+":"+strings.Join(sc.GetActions(), ","))
		}
		slices.Sort(got)
		return got
	}
	alex, err := k.State.SignIn("fixture-alex")
	if err != nil {
		t.Fatal(err)
	}
	own := wikiScopes(issuer.WithSession(context.Background(), alex.ID))
	if !slices.ContainsFunc(own, func(s string) bool { return strings.Contains(s, "publish") }) {
		t.Fatalf("setup: Alex publishes at the wiki on his own session: %v", own)
	}
	viewing, err := k.State.OpenRoleView(context.Background(), alex.ID, state.InstallationID("acme", "wiki"), []string{"viewer"})
	if err != nil {
		t.Fatal(err)
	}
	as := wikiScopes(issuer.WithSession(context.Background(), viewing.ID))
	remi := wikiScopes(person(t, k, "fixture-remi"))
	if !slices.Equal(as, remi) {
		t.Fatalf("Alex as viewer holds %v, Rémi, a viewer, holds %v", as, remi)
	}
	// His own session is untouched, and a role he does not hold is not one he can view as.
	if !slices.Equal(wikiScopes(issuer.WithSession(context.Background(), alex.ID)), own) {
		t.Fatal("opening a view changed the session it came from")
	}
	if _, err := k.State.OpenRoleView(context.Background(), alex.ID, state.InstallationID("acme", "wiki"), []string{"editor"}); err == nil {
		t.Fatal("Alex viewed as a role he does not hold")
	}
}
