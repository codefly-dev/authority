package authority_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// THE FIXTURE (owner, 2026-11-12): every role-gated target gets one team per
// role it declares, `<target>-<role>`, and the same people seated in them
// everywhere. Solution "a" declares installer, author, editor and viewer.
func TestEveryDeclaredRoleGoesToItsConventionalTeam(t *testing.T) {
	h := newHarness(t)
	want := map[string]string{"installer": "a-installer", "author": "a-author", "editor": "a-editor", "viewer": "a-viewer"}
	teams, err := h.svc.RoleTeamsOf(h.ctx, h.inst(acme, "a").ID)
	if err != nil || !reflect.DeepEqual(teams, want) {
		t.Fatalf("teams = %v, %v; want %v", teams, err, want)
	}
	// The host's directory holds the teams first; a team it does not hold is
	// refused by name, and nothing is granted.
	if _, err := h.svc.GrantRoleTeamsAsHost(h.ctx, h.inst(acme, "a").ID); err == nil || !strings.Contains(err.Error(), "not a team of") {
		t.Fatalf("want a refusal naming the missing team, got %v", err)
	}
	if grants, _ := h.svc.ListRoleGrants(h.ctx, h.person("alex"), acme, h.inst(acme, "a").ID); len(grants) != 0 {
		t.Fatalf("a refused pass granted %v", grants)
	}
	for _, team := range want {
		h.store.PutTeam(acme, team)
	}
	for range 2 { // idempotent: a second pass changes nothing
		if teams, err = h.svc.GrantRoleTeamsAsHost(h.ctx, h.inst(acme, "a").ID); err != nil || !reflect.DeepEqual(teams, want) {
			t.Fatalf("teams = %v, %v", teams, err)
		}
	}
	grants, err := h.svc.ListRoleGrants(h.ctx, h.person("alex"), acme, h.inst(acme, "a").ID)
	if err != nil || len(grants) != 4 {
		t.Fatalf("grants = %v, %v", grants, err)
	}
	for _, g := range grants {
		if g.PersonID != "" || want[g.Role] != g.TeamID {
			t.Fatalf("grant %+v is not a role to its conventional team", g)
		}
	}
	// A module that is role-gated by nothing has no team.
	if teams, err := h.svc.RoleTeamsOf(h.ctx, authority.StableInstallationID(acme, "store")); err != nil || len(teams) != 0 {
		t.Fatalf("a roleless module: %v, %v", teams, err)
	}
}

// A cast session reaches what the team holds and nothing else, and the
// session it was opened from keeps every role of the person's own: that is
// what "act as this team" promises, and what "back" restores.
func TestACastHoldsTheTeamsReachAndTheOwnSessionKeepsItsOwn(t *testing.T) {
	h := newHarness(t)
	for _, team := range []string{"a-installer", "a-author", "a-editor", "a-viewer"} {
		h.store.PutTeam(acme, team)
	}
	if _, err := h.svc.GrantRoleTeamsAsHost(h.ctx, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	// bob is a member seated in a-viewer alone; carol in a-editor alone.
	h.store.PutPerson(domain.Person{ID: "bob", Organization: acme, Teams: []string{"a-viewer"}})
	h.store.PutPerson(domain.Person{ID: "carol", Organization: acme, Teams: []string{"a-editor"}})

	// alex administers acme and is granted author on a directly: his own
	// session writes a's notes (an organization role alone reaches no
	// owner's data at an owner-aware solution, RBAC-4a; the direct grant does).
	h.grant("a", "author", "alex")
	own := h.must(h.root("alex", "a"))
	if !holds(own, "a.note", "write") {
		t.Fatal("the administrator's own session does not write: the fixture does not test what it claims")
	}
	// Cast onto a-viewer, he reads and does not write: the cast holds the
	// team's role and not his own direct grant.
	cast, err := h.casting("alex", "a-viewer")
	if err != nil {
		t.Fatalf("an administrator casts onto any team of their organization: %v", err)
	}
	viewing := h.must(h.rootAs(cast, "a"))
	if !holds(viewing, "a.note", "read") || holds(viewing, "a.note", "write") {
		t.Fatalf("the cast holds %v, want a viewer's read alone", effective(viewing))
	}
	// Un-cast: the session she came from is untouched and still writes.
	if again := h.must(h.root("alex", "a")); !holds(again, "a.note", "write") {
		t.Fatal("the own session lost its reach while a cast was open")
	}
	// Bob holds a-viewer's reach on his own session, may cast onto his own
	// team, and is refused the editor team by name: he could not grant it.
	if bob := h.must(h.root("bob", "a")); !holds(bob, "a.note", "read") || holds(bob, "a.note", "write") {
		t.Fatalf("bob holds %v, want a viewer's read alone", effective(bob))
	}
	if _, err := h.casting("bob", "a-viewer"); err != nil {
		t.Fatalf("a member casts onto their own team: %v", err)
	}
	if _, err := h.casting("bob", "a-editor"); err == nil || !strings.Contains(err.Error(), "could not grant") {
		t.Fatalf("bob onto a-editor: want a refusal naming what he could not grant, got %v", err)
	}
}
