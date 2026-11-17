package authority_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

// casting opens a cast onto team for person, as a new session, and returns
// that session's person.
func (h *harness) casting(person, team string) (authority.Person, error) {
	h.t.Helper()
	parent := h.person(person)
	session := person + "-as-team-" + team
	_, err := h.svc.OpenTeamCast(h.ctx, parent, authority.TeamCastRequest{
		Organization: parent.Organization, Team: team, SessionID: session})
	parent.SessionID = session
	return parent, err
}

// THE REQUIREMENT (owner, 2026-11-11): a platform administrator keeps every
// permission and can assume any team membership to test, without their user
// being in that team. "alex" administers acme and belongs to no team here.
func TestAnAdministratorCastsOntoATeamTheyDoNotBelongTo(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "user", "team")

	cast, err := h.casting("alex", "team")
	if err != nil {
		t.Fatalf("an administrator must be able to act as a team they are not in: %v", err)
	}

	// And in that cast they hold what the team holds — the user role — not
	// their own administrator reach.
	issued, err := h.rootAs(cast, "a")
	if err != nil {
		t.Fatalf("issue in a cast: %v", err)
	}
	if holds(issued, "a.thing", "write") {
		t.Error("a cast onto a user team still writes: the administrator's reach was not dropped")
	}
}

// A cast onto a team that is granted nothing says so, rather than handing
// back a session that silently sees nothing.
func TestACastOntoATeamThatHoldsNothingIsRefusedByName(t *testing.T) {
	h := newHarness(t)

	_, err := h.casting("alex", "nobody-granted-this")
	if err == nil {
		t.Fatal("a cast onto a team with no grant must be refused")
	}
	if !strings.Contains(err.Error(), "nothing to act as") {
		t.Errorf("the refusal must say there is nothing to act as, got: %v", err)
	}
}

// A cast is never changed or widened: a session already cast cannot cast again.
func TestACastIsNeverRecast(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "user", "team")

	cast, err := h.casting("alex", "team")
	if err != nil {
		t.Fatalf("first cast: %v", err)
	}
	_, err = h.svc.OpenTeamCast(h.ctx, cast, authority.TeamCastRequest{
		Organization: cast.Organization, Team: "team", SessionID: "another-session"})
	if err == nil {
		t.Fatal("casting from a cast must be refused")
	}
	if !strings.Contains(err.Error(), "already cast") {
		t.Errorf("the refusal must name the existing cast, got: %v", err)
	}
}

// The rule must still REFUSE: a person who may neither act as the team's
// roles nor grant them cannot act as it. Without this the cast is a
// privilege escalation — anyone could be any team.
func TestAPersonWhoCannotGrantCannotActAsTheTeam(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "user", "team")

	// "maya" is an ordinary member of acme: not an administrator, not in the
	// team, and so may neither act as user there nor grant it.
	_, err := h.casting("maya", "team")
	if err == nil {
		t.Fatal("an ordinary person must not be able to act as a team they neither hold nor may grant")
	}
	if !strings.Contains(err.Error(), "could not grant") {
		t.Errorf("the refusal must say they could not grant those roles, got: %v", err)
	}
}

// A role view opened FROM a cast stays inside that cast. This is the escape an
// independent review found and reproduced: the view record carried the viewed
// roles but not the team, so the new session's Cast was empty and HeldRoles
// went back to the person's own direct grants and every team they belong to.
//
// It never exceeded the PERSON — the organisation role is cleared either way —
// but it exceeded the CAST, which is the whole point of casting: "view as a
// user" would then answer from reach a user does not have, and pass.
func TestARoleViewOpenedFromACastStaysInTheCast(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "user", "team")
	// tam belongs to `team`, and separately holds admin on both a and b.
	h.grant("a", "admin", "tam")
	h.grant("b", "admin", "tam")

	cast, err := h.casting("tam", "team")
	if err != nil {
		t.Fatalf("cast onto a team tam belongs to: %v", err)
	}
	// In the cast, tam reaches b through nothing: the team has no grant there.
	if issued, err := h.rootAs(cast, "b"); err == nil && holds(issued, "b.note", "write") {
		t.Fatal("the cast itself already reaches b: the fixture does not test what it claims")
	}

	// Open a role view from the cast, on the installation the team does reach.
	viewed := cast
	viewed.SessionID = "tam-cast-then-view"
	if _, err := h.svc.OpenRoleView(h.ctx, cast, authority.RoleViewRequest{
		Organization: cast.Organization, InstallationID: h.inst(acme, "a").ID,
		SessionID: viewed.SessionID, Roles: []string{"user"},
	}); err != nil {
		t.Fatalf("open a view from a cast: %v", err)
	}

	// The view must still be inside the cast: b stays out of reach.
	issued, err := h.rootAs(viewed, "b")
	if err == nil && holds(issued, "b.note", "write") {
		t.Fatal("a view opened from a cast escaped it: the person's own grants at b came back")
	}
}

// The list a page offers is the choice OpenTeamCast decides, by the same
// rule: an administrator lists every team granted something, with what it
// holds; a person who could not grant a team's roles does not list it; a team
// granted nothing is not listed; a cast lists the one team it acts as.
func TestCastableTeamsListsWhatOpenTeamCastWouldOpen(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "user", "team")
	h.grantTeam("b", "user", "team")
	h.store.PutTeam(acme, "other")
	h.grantTeam("a", "user", "other")
	names := func(teams []authority.CastableTeam) (out []string) {
		for _, team := range teams {
			out = append(out, team.Team)
		}
		return out
	}

	alex := h.person("alex")
	listed, err := h.svc.CastableTeams(h.ctx, alex, alex.Organization)
	if err != nil {
		t.Fatalf("an administrator lists the teams: %v", err)
	}
	if got := strings.Join(names(listed), ","); got != "other,team" {
		t.Fatalf("an administrator lists %q; want every team granted something, sorted: other,team", got)
	}
	var held []string
	for _, h := range listed[1].Holds {
		held = append(held, h.Target+":"+h.Role)
	}
	if slices.Sort(held); strings.Join(held, ",") != "a:user,b:user" {
		t.Fatalf("team holds %v; want user on a and user on b", held)
	}
	for _, team := range listed {
		if _, err := h.svc.OpenTeamCast(h.ctx, alex, authority.TeamCastRequest{Organization: acme, Team: team.Team, SessionID: "listed-" + team.Team}); err != nil {
			t.Fatalf("listed team %q is refused by OpenTeamCast: %v", team.Team, err)
		}
	}

	maya := h.person("maya")
	if listed, err := h.svc.CastableTeams(h.ctx, maya, maya.Organization); err != nil || len(listed) != 0 {
		t.Fatalf("a person who could grant nothing lists %v (%v); want none", names(listed), err)
	}

	cast, err := h.casting("alex", "team")
	if err != nil {
		t.Fatalf("cast: %v", err)
	}
	if listed, err := h.svc.CastableTeams(h.ctx, cast, cast.Organization); err != nil || strings.Join(names(listed), ",") != "team" {
		t.Fatalf("a cast lists %v (%v); want the one team it acts as", names(listed), err)
	}
	if _, err := h.svc.CastableTeams(h.ctx, alex, "another-org"); err == nil {
		t.Fatal("a member of acme listed another organization's teams")
	}
}

// A cast is a live rule, not a decision taken once at open: "a person may act
// as a team whose roles they could grant" is asked again at every issuance
// and every role decision made under the cast. remi holds admin on a, casts
// onto a team holding admin there, and loses the admin: the cast is refused by
// name, and it cannot grant the admin back to the person behind it.
func TestACastEndsWhenThePersonCouldNoLongerGrantTheTeamsRoles(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "remi")
	h.grantTeam("a", "admin", "team")
	cast, err := h.casting("remi", "team")
	if err != nil {
		t.Fatalf("an installation's admin casts onto a team holding roles there: %v", err)
	}
	h.must(h.rootAs(cast, "a"))

	h.revoke("a", "admin", "remi", "")

	_, err = h.rootAs(cast, "a")
	refused(t, err, "could not grant")
	_, err = h.svc.GrantRole(h.ctx, cast, authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "admin", PersonID: "remi"})
	refused(t, err, "could not grant")
	if _, err := h.svc.ListRoleGrants(h.ctx, cast, acme, h.inst(acme, "a").ID); err == nil {
		t.Fatal("a cast that ended still lists the installation's grants")
	}
	if _, err := h.root("remi", "a"); err == nil {
		t.Fatal("the revoked admin was restored")
	}
	// Granted again, the same cast holds again: the rule is read, not stored.
	h.grant("a", "admin", "remi")
	h.must(h.rootAs(cast, "a"))
}

// The cast is one rule over everything the team holds, so losing the right to
// grant on one installation ends what the cast was issued on another: a
// capability issued at b is refused once the person could no longer grant the
// team's role on a.
func TestACapabilityIssuedInACastIsRefusedOnceTheCastEnds(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "remi")
	h.grant("b", "admin", "remi")
	h.grantTeam("a", "admin", "team")
	h.grantTeam("b", "user", "team")
	cast, err := h.casting("remi", "team")
	if err != nil {
		t.Fatal(err)
	}
	atB := h.must(h.rootAs(cast, "b"))
	if err := h.check(atB); err != nil {
		t.Fatalf("a cast's capability checks while the cast holds: %v", err)
	}

	h.revoke("a", "admin", "remi", "")

	refused(t, h.check(atB), "could not grant")
	_, err = h.rootAs(cast, "b")
	refused(t, err, "could not grant")
}

// The team gains a role the person could never grant: ines administers a
// only, and the team is later granted admin on b. The rule is about the team,
// so the whole cast is refused (as a fresh cast is), on b and on a alike; it
// is never issued the new role, and never grants with it.
func TestACastEndsWhenTheTeamGainsARoleThePersonCouldNotGrant(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "admin", "ines")
	h.grantTeam("a", "user", "team")
	cast, err := h.casting("ines", "team")
	if err != nil {
		t.Fatalf("an installation's admin casts onto a team holding roles there: %v", err)
	}
	h.must(h.rootAs(cast, "a"))

	h.grantTeam("b", "admin", "team")

	_, err = h.rootAs(cast, "b")
	refused(t, err, "could not grant")
	_, err = h.svc.GrantRole(h.ctx, cast, authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "b").ID, Role: "admin", PersonID: "ines"})
	refused(t, err, "could not grant")
	_, err = h.rootAs(cast, "a")
	refused(t, err, "could not grant")
	_, err = h.svc.OpenTeamCast(h.ctx, h.person("ines"), authority.TeamCastRequest{Organization: acme, Team: "team", SessionID: "a-fresh-cast"})
	refused(t, err, "could not grant")

	// The team's role on b ends, and the same cast holds again.
	h.revoke("b", "admin", "", "team")
	h.must(h.rootAs(cast, "a"))
}

// Revoking a team's role ends the capabilities held through it at once: a
// member's, and a cast's, whose person is by design not a member. Nobody
// else's are touched.
func TestRevokingATeamsRoleEndsACapabilityHeldThroughACast(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "user", "team")
	h.grant("a", "admin", "remi")
	h.grant("b", "user", "maya")
	casts := map[string]authority.Issued{}
	for _, person := range []string{"alex", "remi"} {
		cast, err := h.casting(person, "team")
		if err != nil {
			t.Fatalf("%s casts onto the team: %v", person, err)
		}
		casts[person] = h.must(h.rootAs(cast, "a"))
	}
	member := h.must(h.root("tam", "a"))
	unrelated := h.must(h.root("maya", "b"))

	h.revoke("a", "user", "", "team")

	if err := h.check(member); err == nil {
		t.Fatal("a team revoke left a member's capability valid")
	}
	for person, issued := range casts {
		if err := h.check(issued); err == nil {
			t.Fatalf("a team revoke left the capability %s holds through a cast onto it valid", person)
		}
	}
	if err := h.check(unrelated); err != nil {
		t.Fatalf("a team revoke on a ended the capability of a person who could not act as the team: %v", err)
	}
}
