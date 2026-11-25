package session_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	sessionv1 "gateway/pkg/gen/host/session/v1"
	"gateway/plugins/session"
)

// A team's members are changed over the session interface by the
// organisation's administrator, on their own session, in a run started on its
// fixture, and by nobody else and nowhere else. The person named is a person
// of the administrator's organisation and the team a team of it.
func TestAFixtureTeamsMembersAreChangedByTheOrganisationsAdministratorAlone(t *testing.T) {
	k := testkit.New(t)
	p := &session.Plugin{State: k.State, Fixture: true}
	alice, maya, zoe := signIn(t, p, "dev-alice"), signIn(t, p, "fixture-maya"), signIn(t, p, "fixture-zoe")
	remove := func(bearer, team, person string) error {
		_, err := p.RemoveFixtureTeamMember(as(bearer), &sessionv1.RemoveFixtureTeamMemberRequest{TeamId: team, PersonId: person})
		return err
	}
	add := func(bearer, team, person string) error {
		_, err := p.AddFixtureTeamMember(as(bearer), &sessionv1.AddFixtureTeamMemberRequest{TeamId: team, PersonId: person})
		return err
	}
	teams := func() []string {
		t.Helper()
		for _, person := range k.State.FixturePeople() {
			if person.ID == "maya" {
				return person.Teams
			}
		}
		t.Fatal("the fixture has no maya")
		return nil
	}
	epoch := func() string {
		t.Helper()
		current, err := p.Current(as(maya.GetBearer()), &sessionv1.CurrentRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return current.GetGrantEpoch()
	}
	if !slices.Contains(teams(), "finance") {
		t.Fatalf("the fixture's maya belongs to %v, not finance: the case proves nothing", teams())
	}

	// Nowhere but a run started on its fixture, whoever asks.
	closed := &session.Plugin{State: k.State}
	if _, err := closed.RemoveFixtureTeamMember(as(alice.GetBearer()), &sessionv1.RemoveFixtureTeamMemberRequest{TeamId: "finance", PersonId: "maya"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a removal on a host not started on a fixture: %v", err)
	}
	if _, err := closed.AddFixtureTeamMember(as(alice.GetBearer()), &sessionv1.AddFixtureTeamMemberRequest{TeamId: "engineering", PersonId: "maya"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an addition on a host not started on a fixture: %v", err)
	}

	// Nobody but the organisation's administrator, on their own session.
	wiki := state.InstallationID("acme", "wiki")
	if err := k.State.GrantRole(domain.RoleGrant{InstallationID: wiki, Role: state.AdminRole, PersonID: "alice"}); err != nil {
		t.Fatal(err)
	}
	view, err := p.OpenRoleView(as(alice.GetBearer()), &sessionv1.OpenRoleViewRequest{InstallationId: wiki, Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	cast, err := p.OpenTeamCast(as(alice.GetBearer()), &sessionv1.OpenTeamCastRequest{TeamId: "finance"})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		bearer string
		want   codes.Code
	}{
		"no bearer":                              {"", codes.Unauthenticated},
		"a bearer naming no session":             {"not-a-session", codes.Unauthenticated},
		"the member themself":                    {maya.GetBearer(), codes.PermissionDenied},
		"the administrator's role view":          {view.GetBearer(), codes.PermissionDenied},
		"the administrator's cast onto the team": {cast.GetBearer(), codes.PermissionDenied},
		"another organisation's administrator":   {zoe.GetBearer(), codes.NotFound},
	} {
		if err := remove(tc.bearer, "finance", "maya"); status.Code(err) != tc.want {
			t.Errorf("a removal by %s: want %v, got %v", name, tc.want, err)
		}
		if err := add(tc.bearer, "engineering", "maya"); status.Code(err) != tc.want {
			t.Errorf("an addition by %s: want %v, got %v", name, tc.want, err)
		}
	}
	// What the call names is the administrator's organisation's, or not found.
	for name, err := range map[string]error{
		"a person of another organisation": add(alice.GetBearer(), "finance", "zoe"),
		"a person who does not exist":      remove(alice.GetBearer(), "finance", "nobody"),
		"another organisation's team":      add(alice.GetBearer(), "ops", "maya"),
		"a team that does not exist":       add(alice.GetBearer(), "no-such-team", "maya"),
		"no team":                          remove(alice.GetBearer(), "", "maya"),
		"no person":                        add(alice.GetBearer(), "finance", ""),
	} {
		if status.Code(err) != codes.NotFound {
			t.Errorf("%s: want not found, got %v", name, err)
		}
	}
	if got := teams(); !slices.Equal(got, []string{"finance"}) {
		t.Fatalf("a refused call changed maya's teams to %v", got)
	}

	// The administrator's own call: out, and what she holds is different;
	// back in, and different again. Either one twice changes nothing more.
	before := epoch()
	for range 2 {
		if err := remove(alice.GetBearer(), "finance", "maya"); err != nil {
			t.Fatal(err)
		}
	}
	if got := teams(); len(got) != 0 {
		t.Fatalf("removed, maya still belongs to %v", got)
	}
	out := epoch()
	if out == before {
		t.Fatal("the grant epoch of a person taken out of a team did not move")
	}
	if fresh := signIn(t, p, "fixture-maya"); len(fresh.GetTeamIds()) != 0 {
		t.Fatalf("signed in after the removal, maya belongs to %v", fresh.GetTeamIds())
	}
	for range 2 {
		if err := add(alice.GetBearer(), "finance", "maya"); err != nil {
			t.Fatal(err)
		}
	}
	if got := teams(); !slices.Equal(got, []string{"finance"}) {
		t.Fatalf("put back, maya belongs to %v", got)
	}
	if epoch() == out {
		t.Fatal("the grant epoch of a person put in a team did not move")
	}
}
