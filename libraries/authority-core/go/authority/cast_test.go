package authority_test

import (
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
	h.grantTeam("a", "viewer", "team")

	cast, err := h.casting("alex", "team")
	if err != nil {
		t.Fatalf("an administrator must be able to act as a team they are not in: %v", err)
	}

	// And in that cast they hold what the team holds — the viewer role — not
	// their own administrator reach.
	issued, err := h.rootAs(cast, "a")
	if err != nil {
		t.Fatalf("issue in a cast: %v", err)
	}
	if holds(issued, "a.thing", "write") {
		t.Error("a cast onto a viewer team still writes: the administrator's reach was not dropped")
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
	h.grantTeam("a", "viewer", "team")

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
	h.grantTeam("a", "editor", "team")

	// "maya" is an ordinary member of acme: not an administrator, not in the
	// team, and so may neither act as editor there nor grant it.
	_, err := h.casting("maya", "team")
	if err == nil {
		t.Fatal("an ordinary person must not be able to act as a team they neither hold nor may grant")
	}
	if !strings.Contains(err.Error(), "widen") {
		t.Errorf("the refusal must say it would widen them, got: %v", err)
	}
}

// A role view opened FROM a cast stays inside that cast. This is the escape an
// independent review found and reproduced: the view record carried the viewed
// roles but not the team, so the new session's Cast was empty and HeldRoles
// went back to the person's own direct grants and every team they belong to.
//
// It never exceeded the PERSON — the organisation role is cleared either way —
// but it exceeded the CAST, which is the whole point of casting: "view as a
// viewer" would then answer from reach a viewer does not have, and pass.
func TestARoleViewOpenedFromACastStaysInTheCast(t *testing.T) {
	h := newHarness(t)
	h.grantTeam("a", "viewer", "team")
	// tam belongs to `team`, and separately holds author on both a and b.
	h.grant("a", "author", "tam")
	h.grant("b", "author", "tam")

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
		SessionID: viewed.SessionID, Roles: []string{"viewer"},
	}); err != nil {
		t.Fatalf("open a view from a cast: %v", err)
	}

	// The view must still be inside the cast: b stays out of reach.
	issued, err := h.rootAs(viewed, "b")
	if err == nil && holds(issued, "b.note", "write") {
		t.Fatal("a view opened from a cast escaped it: the person's own grants at b came back")
	}
}
