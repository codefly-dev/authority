package state_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"gateway/pkg/business/testkit"
)

// The fixture a run is given is the cast a walk needs and nobody else: Dana
// the admin, Carol the user, Bob refused (handbook: a page has two roles,
// admin and user). The sign-in page lists FixturePeople, so a person added
// here is a person every playground offers; the test kit's matrix of other
// organisations and refusal cases lives in testkit/fixture.yaml instead.
func TestTheShippedFixtureIsTheCastAndNobodyElse(t *testing.T) {
	k := testkit.Bare(t)
	data, err := os.ReadFile(testkit.ShippedFixturePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := k.State.LoadFixture(context.Background(), data); err != nil {
		t.Fatalf("the shipped fixture does not load: %v", err)
	}
	var ids []string
	byID := map[string][]string{}
	for _, person := range k.State.FixturePeople() {
		ids = append(ids, person.ID)
		byID[person.ID] = person.Roles
		if person.Organization != "acme" {
			t.Errorf("%s belongs to %q: the shipped fixture has one organisation, acme", person.ID, person.Organization)
		}
		if len(person.Teams) != 0 {
			t.Errorf("%s is seated on %v by hand: the `*` row seats the target teams", person.ID, person.Teams)
		}
	}
	if !slices.Equal(ids, []string{"dana", "carol", "bob"}) {
		t.Fatalf("the shipped fixture lists %v; a walk needs dana, carol and bob, and nobody else", ids)
	}
	if !slices.Equal(byID["dana"], []string{"admin"}) || len(byID["carol"]) != 0 || len(byID["bob"]) != 0 {
		t.Fatalf("organisation roles: dana %v, carol %v, bob %v; only Dana administers Acme", byID["dana"], byID["carol"], byID["bob"])
	}
	for _, token := range []string{"dev-dana", "dev-carol", "dev-bob"} {
		if _, err := k.State.SignIn(token); err != nil {
			t.Errorf("%s cannot sign in: %v", token, err)
		}
	}
	for _, gone := range []string{"dev-admin", "dev-alice", "fixture-dev", "fixture-maya", "fixture-no-roles"} {
		if _, err := k.State.SignIn(gone); err == nil {
			t.Errorf("%s still signs in from the shipped fixture", gone)
		}
	}
}
