package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// teamRemoval is the host removing a member from a team: over the session
// interface's RemoveFixtureTeamMember, called by the organisation's
// administrator, on a host that serves it (the fixture names no
// RemoveFromTeam), and by the host's own path otherwise (RemoveFromTeam: a
// host that signs real people in changes membership in its own product
// surface). The authority reads a person's
// teams from the host and is told nothing of a removal unless the host tells
// it, so the suite holds the host to the result, by the next call:
//   - every capability the member was issued through the team's role is
//     refused by Check, naming the revocation: their call through A, and the
//     store's own hop on it, which is sealed to the store's installation, not
//     to the one the team's role is on;
//   - ListResources answers such a capability nothing, refusing it;
//   - a fresh ask at A is refused "holds no role";
//   - acting as the team is refused: the session they had cast onto it issues
//     nothing more and what it was issued is refused; a new cast is refused,
//     naming that they could not grant the team's roles; ListCastableTeams
//     offers them the team no more;
//   - what only the team gave is all they lose, and they keep the rest only
//     through what they are issued from then on: the capability they held
//     through the role granted to them directly on B is refused with the
//     others, naming the revocation, and that role is issued again, freshly;
//     another member of the team is untouched;
//   - where the host serves the membership calls, the call is the
//     administrator's alone (the leaver, another member and another
//     organisation's administrator are each refused and change nothing),
//     and a person put back in the team (AddFixtureTeamMember) is issued
//     through the team's role again, freshly: nothing issued before they
//     left is revived.
//
// It runs with Team holding user on A, and leaves it so, the leaver out of
// the team.
func (sp *principalSuite) teamRemoval(t *testing.T) {
	t.Helper()
	f := sp.f
	A, B, leaver := f.A, f.B, f.TeamLeaver
	sp.grant(t, B, "user", sp.person(t, leaver))
	defer sp.revoke(t, B, "user", sp.person(t, leaver))

	through := sp.must(t)(sp.through(t, leaver, A, "store"))
	deeper := sp.must(t)(sp.hop(t, through))
	if sealed, role := str(msg(msg(deeper, "context"), "seal"), "installation_id"), str(sp.ensure(t, f.Organization, A), "id"); sealed == role {
		t.Fatalf("the store's hop is sealed to %s, the installation the team's role is on: it proves nothing of a capability sealed elsewhere", sealed)
	}
	own := sp.must(t)(sp.through(t, leaver, B, "store"))
	as, err := sp.cast(t, leaver, f.Team)
	if err != nil {
		t.Fatalf("a member must be able to act as their team: %v", err)
	}
	asTeam := sp.must(t)(sp.through(t, as, A, "store"))
	for name, capability := range map[string]error{"the call through the team's role": sp.check(through), "the store's hop on it": sp.check(deeper),
		"the call through their own role": sp.check(own), "the call made as the team": sp.check(asTeam)} {
		if capability != nil {
			t.Fatalf("%s is refused while they are a member: %v", name, capability)
		}
	}

	sp.removeFromTeam(t, leaver, f.Team)

	refused(t, sp.check(through), codes.PermissionDenied, "revoked")
	refused(t, sp.check(deeper), codes.PermissionDenied, "revoked")
	refused(t, sp.check(asTeam), codes.PermissionDenied, "")
	_, err = sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{"token": str(through, "token"), "audience": f.Store, "resource_kind": f.Kind, "action": "read"})
	refused(t, err, codes.PermissionDenied, "revoked")
	_, err = sp.root(t, leaver, A)
	refused(t, err, codes.PermissionDenied, "holds no role")

	_, err = sp.through(t, as, A, "store")
	refused(t, err, codes.PermissionDenied, "")
	_, err = sp.cast(t, leaver, f.Team)
	refused(t, err, codes.PermissionDenied, "could not grant")
	if got := sp.castable(t, leaver); got[f.Team] != nil {
		t.Fatalf("a person removed from the team is still offered it to act as: %v", got)
	}

	// The role held directly survives, through a fresh capability only.
	refused(t, sp.check(own), codes.PermissionDenied, "revoked")
	exactOwnedScope(t, msg(sp.must(t)(sp.through(t, leaver, B, "store")), "context"), f.Kind, []string{"read"}, sp.principal(t, f.Organization, B))
	exactOwnedScope(t, msg(sp.must(t)(sp.through(t, f.TeamMember, A, "store")), "context"), f.Kind, []string{"read"}, sp.principal(t, f.Organization, A))

	if !sp.membershipOverTheWire() {
		return
	}
	// Put back by the administrator, they are issued through the team's role
	// again, and nothing issued before they left is revived.
	sp.must(t)(sp.c.call(sp.as(t, f.Admin), sessionService, "AddFixtureTeamMember", map[string]any{"team_id": f.Team, "person_id": sp.personID(t, leaver)}))
	again := sp.must(t)(sp.through(t, leaver, A, "store"))
	if err := sp.check(again); err != nil {
		t.Fatalf("the capability issued once they were put back in the team is refused: %v", err)
	}
	refused(t, sp.check(through), codes.PermissionDenied, "revoked")
	refused(t, sp.check(deeper), codes.PermissionDenied, "revoked")
	// The call is the organisation's administrator's alone, on their own
	// session: anybody else is refused and the member stays.
	change := map[string]any{"team_id": f.Team, "person_id": sp.personID(t, leaver)}
	for name, caller := range map[string]string{"the member themself": leaver, "another member of the team": f.TeamMember, "a member who administers nothing": f.Member} {
		for _, method := range []string{"RemoveFixtureTeamMember", "AddFixtureTeamMember"} {
			if _, err := sp.c.call(sp.as(t, caller), sessionService, method, change); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("%s by %s: want PermissionDenied, got %v", method, name, err)
			}
		}
	}
	// Another organisation's administrator names a person who is none of
	// theirs: not found, and nothing changes here.
	if _, err := sp.c.call(sp.as(t, f.OtherAdmin), sessionService, "RemoveFixtureTeamMember", change); status.Code(err) != codes.NotFound {
		t.Fatalf("RemoveFixtureTeamMember by another organisation's administrator: want NotFound, got %v", err)
	}
	if _, err := sp.c.call(sp.ctx, sessionService, "RemoveFixtureTeamMember", change); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("RemoveFixtureTeamMember with no bearer: want Unauthenticated, got %v", err)
	}
	if err := sp.check(again); err != nil {
		t.Fatalf("a refused membership call ended what the member holds: %v", err)
	}
	// A team that is none of the organisation's has no member to add.
	if _, err := sp.c.call(sp.as(t, f.Admin), sessionService, "AddFixtureTeamMember", map[string]any{"team_id": f.OtherTeam, "person_id": sp.personID(t, leaver)}); status.Code(err) != codes.NotFound {
		t.Fatalf("AddFixtureTeamMember to another organisation's team: want NotFound, got %v", err)
	}
	// Removed again, as the cases after this one expect; twice changes nothing.
	sp.removeFromTeam(t, leaver, f.Team)
	sp.removeFromTeam(t, leaver, f.Team)
	refused(t, sp.check(again), codes.PermissionDenied, "revoked")
	_, err = sp.root(t, leaver, A)
	refused(t, err, codes.PermissionDenied, "holds no role")
	exactOwnedScope(t, msg(sp.must(t)(sp.through(t, leaver, B, "store")), "context"), f.Kind, []string{"read"}, sp.principal(t, f.Organization, B))
}

// sessionService is the session interface's service.
const sessionService = "host.session.v1.SessionService"

// membershipOverTheWire is whether the suite changes team membership through
// the session interface: the fixture names no RemoveFromTeam of the host's
// own. Such a host publishes and serves RemoveFixtureTeamMember and
// AddFixtureTeamMember.
func (sp *principalSuite) membershipOverTheWire() bool { return sp.f.RemoveFromTeam == nil }

// removeFromTeam takes the person signed in by token out of team: by the
// session interface's RemoveFixtureTeamMember as the organisation's
// administrator, or by the host's own path where the fixture names one.
func (sp *principalSuite) removeFromTeam(t *testing.T, token, team string) {
	t.Helper()
	if !sp.membershipOverTheWire() {
		if err := sp.f.RemoveFromTeam(sp.ctx, sp.personID(t, token), team); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := sp.c.call(sp.as(t, sp.f.Admin), sessionService, "RemoveFixtureTeamMember", map[string]any{"team_id": team, "person_id": sp.personID(t, token)}); err != nil {
		t.Fatalf("RemoveFixtureTeamMember(%s, %s) as the administrator: %v", team, token, err)
	}
}

// membershipProblem is what a fixture that names no RemoveFromTeam lacks,
// or empty: the published contract must then carry the membership calls.
func membershipProblem(c *client, hook func(ctx context.Context, personID, team string) error) string {
	if hook != nil {
		return ""
	}
	for _, method := range []string{"RemoveFixtureTeamMember", "AddFixtureTeamMember"} {
		if !c.hasElement(sessionService, method) {
			return "the fixture names no RemoveFromTeam and the published contract has no " + sessionService + "." + method
		}
	}
	return ""
}
