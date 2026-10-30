package state_test

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// The fixture is the local host's team directory: a team it lists exists with
// nobody in it, and a team it seats a person in exists too.
func TestTheFixtureTeamDirectoryHoldsEmptyAndSeatedTeams(t *testing.T) {
	k := testkit.New(t)
	if err := k.State.LoadFixture(context.Background(), []byte(`teams:
  - {organization: acme, id: reviewers}
people:
  - {id: sam, fixture_token: fixture-sam, organization: acme, roles: [], teams: [seated]}
`)); err != nil {
		t.Fatal(err)
	}
	inst := state.InstallationID("acme", "wiki")
	for _, team := range []string{"reviewers", "seated", "finance"} {
		if _, err := k.State.Service().GrantRoleAsHost(context.Background(), authority.RoleRequest{Organization: "acme", InstallationID: inst, Role: "viewer", TeamID: team}); err != nil {
			t.Fatalf("team %s: %v", team, err)
		}
	}
	for _, team := range []string{"ops", "nobody"} {
		_, err := k.State.Service().GrantRoleAsHost(context.Background(), authority.RoleRequest{Organization: "acme", InstallationID: inst, Role: "viewer", TeamID: team})
		if err == nil || !strings.Contains(err.Error(), "not a team of") {
			t.Fatalf("team %s: want a refusal naming not a team of, got %v", team, err)
		}
	}
	for _, bad := range []string{"teams: [{organization: initech, id: x}]", "teams: [{organization: acme}]"} {
		if err := testkit.New(t).State.LoadFixture(context.Background(), []byte(bad)); err == nil || !strings.Contains(err.Error(), "fixture: team") {
			t.Fatalf("%s: want a fixture refusal, got %v", bad, err)
		}
	}
}
