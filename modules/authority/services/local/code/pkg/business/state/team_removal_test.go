package state_test

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// LeaveTeam is this host's one way to remove a member from a team while it
// runs, and it tells the core the person changed: what only the team's role
// gave them is refused by the next check, a fresh ask holds no role, the team
// is theirs to act as no more, and another member keeps theirs. The fixture
// and the composition seat people at boot, before anything is issued, and
// never unseat one.
func TestLeavingATeamEndsWhatOnlyTheTeamsRoleGave(t *testing.T) {
	k := testkit.New(t)
	ctx := context.Background()
	if err := k.State.LoadFixture(ctx, []byte(`people:
  - {id: sam, fixture_token: fixture-sam, organization: acme, roles: [], teams: [reviewers]}
  - {id: sal, fixture_token: fixture-sal, organization: acme, roles: [], teams: [reviewers]}
`)); err != nil {
		t.Fatal(err)
	}
	svc := k.State.Service()
	if _, err := svc.GrantRoleAsHost(ctx, authority.RoleRequest{Organization: "acme", InstallationID: state.InstallationID("acme", "wiki"), Role: "user", TeamID: "reviewers"}); err != nil {
		t.Fatal(err)
	}
	before, err := k.PersonIssue(t, "sam", "wiki")
	if err != nil {
		t.Fatalf("a member of the granted team is issued nothing: %v", err)
	}
	if _, _, err := svc.Check(ctx, before.GetToken(), "wiki"); err != nil {
		t.Fatal(err)
	}
	sam := authority.Person{ID: "sam", Organization: "acme", SessionID: "sam-after"}
	if teams, err := svc.CastableTeams(ctx, sam, "acme"); err != nil || len(teams) != 1 || teams[0].Team != "reviewers" {
		t.Fatalf("a member is offered %v to act as (%v), want their team", teams, err)
	}

	if err := k.State.LeaveTeam(ctx, "sam", "reviewers"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := svc.Check(ctx, before.GetToken(), "wiki"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("the capability the team's role gave is checked after its holder left the team: %v", err)
	}
	if _, _, _, err := svc.CheckMethod(ctx, before.GetToken(), "wiki", "", false); err == nil {
		t.Fatal("the hop's check still admits what the team's role gave")
	}
	if _, err := k.PersonIssue(t, "sam", "wiki"); err == nil || !strings.Contains(err.Error(), "holds no role") {
		t.Fatalf("a person who left the team is issued its role: %v", err)
	}
	if teams, err := svc.CastableTeams(ctx, sam, "acme"); err != nil || len(teams) != 0 {
		t.Fatalf("a person who left the team is still offered %v to act as (%v)", teams, err)
	}
	if _, err := svc.OpenTeamCast(ctx, authority.Person{ID: "sam", Organization: "acme", SessionID: "sam-own"},
		authority.TeamCastRequest{Organization: "acme", Team: "reviewers", SessionID: "sam-cast"}); err == nil || !strings.Contains(err.Error(), "could not grant") {
		t.Fatalf("a person who left the team acts as it: %v", err)
	}
	if _, err := k.PersonIssue(t, "sal", "wiki"); err != nil {
		t.Fatalf("sam leaving ended sal's access: %v", err)
	}
}
