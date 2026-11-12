package conformance

import (
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
)

// teamCast is SessionService.OpenTeamCast: a person fixes a session to act as
// a member of one team and of nothing else, so that what a member of the team
// sees can be checked by someone whose own reach answers everything. The rule
// is the authority's and is one rule: a person acts as a team whose roles they
// could grant, member of it or not.
//   - an administrator who is not in the team casts onto it, and the cast holds
//     exactly what the team's role holds, at the solution and at the store
//     through its binding; an ask beyond it is refused "widens", and the cast
//     administers nothing: it cannot grant a role;
//   - a member of the team casts onto their own team;
//   - a person who could not grant the team's roles is refused, saying so; a
//     team granted nothing is not found, saying there is nothing to act as; a
//     cast is never recast; another organization's member is refused;
//   - the session says which team it acts as, and names no other team and no
//     organization role; the session it was opened from is untouched.
func (sp *principalSuite) teamCast(t *testing.T) {
	t.Helper()
	if !sp.c.hasElement("host.session.v1.SessionService", "OpenTeamCast") || !sp.c.hasElement("host.session.v1.Session", "cast_team_id") {
		t.Fatal("the published contract lacks host.session.v1.SessionService.OpenTeamCast or Session.cast_team_id: a person's session cast onto a team")
	}
	f := sp.f
	A := f.A
	u := sp.principal(t, f.Organization, A)
	sp.grant(t, A, "viewer", map[string]any{"team_id": f.Team})
	defer sp.revoke(t, A, "viewer", map[string]any{"team_id": f.Team})

	cast := func(t *testing.T, from, team string) (string, error) {
		t.Helper()
		out, err := sp.c.call(sp.as(t, from), "host.session.v1.SessionService", "OpenTeamCast", map[string]any{"team_id": team})
		if err != nil {
			return "", err
		}
		name := "team-cast:" + str(out, "session_id")
		sp.sessions[name] = out
		return name, nil
	}

	for who, from := range map[string]string{"an administrator who is not in the team": f.Admin, "a member of the team": f.TeamMember} {
		t.Run(who, func(t *testing.T) {
			as, err := cast(t, from, f.Team)
			if err != nil {
				t.Fatalf("%s must be able to act as the team: %v", who, err)
			}
			exactOwnedScope(t, msg(sp.must(t)(sp.root(t, as, A)), "context"), A.Solution+".note", []string{"read"}, u)
			exactOwnedScope(t, msg(sp.must(t)(sp.through(t, as, A, "store")), "context"), f.Kind, []string{"read"}, u)
			_, err = sp.through(t, as, A, "store", sp.owned(f.Kind, []string{"write"}, u))
			refused(t, err, codes.PermissionDenied, "widens")
			_, err = sp.c.call(sp.as(t, as), "host.installation.v1.InstallationService", "GrantRole", map[string]any{
				"organization_id": f.Organization, "installation_id": str(sp.ensure(t, f.Organization, A), "id"), "role": "author", "team_id": f.Team})
			refused(t, err, codes.PermissionDenied, "belongs to another organization") // what a viewer is answered
			_, err = cast(t, as, f.Team)
			refused(t, err, codes.PermissionDenied, "already cast")

			current := sp.must(t)(sp.c.call(sp.as(t, as), "host.session.v1.SessionService", "Current", nil))
			if str(current, "cast_team_id") != f.Team || !slices.Equal(listStrings(current, "team_ids"), []string{f.Team}) || len(listStrings(current, "roles")) != 0 {
				t.Fatalf("Current says the cast acts as team %q, of teams %v, with roles %v; want team %s alone and no role",
					str(current, "cast_team_id"), listStrings(current, "team_ids"), listStrings(current, "roles"), f.Team)
			}
		})
	}
	// The session a cast was opened from is untouched: it is not a cast, and
	// the administrator still administers from it.
	if own := sp.must(t)(sp.c.call(sp.as(t, f.Admin), "host.session.v1.SessionService", "Current", nil)); str(own, "cast_team_id") != "" {
		t.Fatalf("the session a cast was opened from says it is cast onto %q", str(own, "cast_team_id"))
	}
	sp.grant(t, A, "author", sp.person(t, f.Member))
	sp.revoke(t, A, "author", sp.person(t, f.Member))

	_, err := cast(t, f.Member, f.Team)
	refused(t, err, codes.PermissionDenied, "could not grant")
	_, err = cast(t, f.Admin, f.EmptyTeam)
	refused(t, err, codes.NotFound, "nothing to act as")
	_, err = cast(t, f.Admin, "")
	refused(t, err, codes.InvalidArgument, "names the team")
	if _, err = cast(t, f.OtherMember, f.Team); err == nil {
		t.Fatal("a member of another organization was cast onto this organization's team")
	}
}
