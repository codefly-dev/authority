package decide

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// A cast onto a team holds exactly what that team is granted: not the
// person's own direct grant, not another team they belong to, and not the
// organisation role they would otherwise carry. That is the whole point —
// an administrator asking "what does a member of this team see" must be
// that and nothing more, or the answer proves nothing.
func TestACastHoldsTheTeamsGrantsAndNothingElse(t *testing.T) {
	inst := domain.Installation{ID: "inst-1", Target: "wiki"}
	grants := []domain.RoleGrant{
		{InstallationID: "inst-1", TeamID: "wiki-user", Role: "user"},
		{InstallationID: "inst-1", TeamID: "wiki-admin", Role: "admin"},
		{InstallationID: "inst-1", PersonID: "p1", Role: "admin"},
	}

	// The person's own session: their direct grant and both their teams.
	own := domain.Person{ID: "p1", Teams: []string{"wiki-user", "wiki-admin"}}
	if got := HeldRoles(own, inst, grants); !slices.Equal(got, []string{"admin", "user"}) {
		t.Fatalf("own session: want admin+user, got %v", got)
	}

	// Cast onto wiki-user: only that team's grant survives, not the admin
	// they hold directly and through their other team.
	cast := domain.Person{ID: "p1", Teams: []string{"wiki-user", "wiki-admin"}, Cast: "wiki-user"}
	if got := HeldRoles(cast, inst, grants); !slices.Equal(got, []string{"user"}) {
		t.Fatalf("cast onto wiki-user: want only user, got %v", got)
	}

	// A cast onto a team the person does NOT belong to still holds exactly
	// that team's grants: membership is not what a cast reads. Whether the
	// person may name it is the grant rule's answer, decided when the cast
	// is opened and wherever the cast session is read, not here.
	stranger := domain.Person{ID: "p2", Teams: nil, Cast: "wiki-admin"}
	if got := HeldRoles(stranger, inst, grants); !slices.Equal(got, []string{"admin"}) {
		t.Fatalf("cast without membership: want only admin, got %v", got)
	}

	// A cast onto a team with no grant on this installation reaches nothing.
	none := domain.Person{ID: "p1", Teams: []string{"wiki-user"}, Cast: "finance"}
	if got := HeldRoles(none, inst, grants); len(got) != 0 {
		t.Fatalf("cast onto an ungranted team: want nothing, got %v", got)
	}
}

// A role view may narrow a cast further; the order never widens.
func TestARoleViewNarrowsACastFurther(t *testing.T) {
	inst := domain.Installation{ID: "inst-1", Target: "wiki"}
	grants := []domain.RoleGrant{
		{InstallationID: "inst-1", TeamID: "t", Role: "admin"},
		{InstallationID: "inst-1", TeamID: "t", Role: "user"},
	}
	p := domain.Person{ID: "p1", Cast: "t", View: map[string][]string{"inst-1": {"user"}}}
	if got := HeldRoles(p, inst, grants); !slices.Equal(got, []string{"user"}) {
		t.Fatalf("view over cast: want only user, got %v", got)
	}
}
