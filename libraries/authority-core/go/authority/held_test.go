package authority_test

import (
	"fmt"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// heldBy is what HeldInstallations answers person at org, as "<target>:<roles>".
func (h *harness) heldBy(person authority.Person, org string) []string {
	h.t.Helper()
	held, err := h.svc.HeldInstallations(h.ctx, person, org)
	if err != nil {
		h.t.Fatalf("%s reading what they hold at %s: %v", person.ID, org, err)
	}
	var out []string
	for _, i := range held {
		if i.Installation.Organization != org || i.Installation.ID != h.inst(org, i.Installation.Target).ID {
			h.t.Fatalf("%s at %s was answered another organization's installation: %+v", person.ID, org, i.Installation)
		}
		out = append(out, fmt.Sprintf("%s:%v", i.Installation.Target, i.Roles))
	}
	return out
}

func heldIs(t *testing.T, who string, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s holds %v, want %v", who, got, want)
	}
}

// A member's navigation lists exactly the installations they hold a role on,
// directly or through a team, with those roles; holding nothing is an empty
// list, not a refusal. A revoke, leaving the team, an uninstall drop it at
// once, and no other organization's installation is ever listed.
func TestHeldInstallationsAreTheCallersOwnRoles(t *testing.T) {
	h := newHarness(t)
	maya, tam, tal := h.person("maya"), h.person("tam"), h.person("tal")

	for _, p := range []authority.Person{maya, tam, h.admin(acme)} {
		heldIs(t, p.ID, h.heldBy(p, acme))
	}
	h.grant("a", "viewer", "maya")
	h.grant("a", "editor", "maya")
	h.grantTeam("b", "viewer", "team")
	h.grant("b", "author", "tam")
	heldIs(t, "maya", h.heldBy(maya, acme), "a:[editor viewer]")
	heldIs(t, "tam", h.heldBy(tam, acme), "b:[author viewer]")
	heldIs(t, "tal", h.heldBy(tal, acme), "b:[viewer]")
	heldIs(t, "alex, an administrator holding no role", h.heldBy(h.admin(acme), acme))

	// Another organization's installation of the same solution is its own.
	if _, err := h.svc.GrantRole(h.ctx, h.admin(globex), authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, Role: "viewer", PersonID: "omar"}); err != nil {
		t.Fatal(err)
	}
	heldIs(t, "omar", h.heldBy(h.person("omar"), globex), "a:[viewer]")
	heldIs(t, "maya", h.heldBy(maya, acme), "a:[editor viewer]")
	// Nobody reads acme's from globex, its administrator included.
	for _, p := range []authority.Person{h.person("omar"), h.admin(globex)} {
		_, err := h.svc.HeldInstallations(h.ctx, p, acme)
		code(t, err, domain.Denied)
		refused(t, err, `the installations held at organization "acme" are read by a member of it, signed in there`)
	}
	// A member of acme reading from a session opened elsewhere is refused too.
	_, err := h.svc.HeldInstallations(h.ctx, authority.Person{ID: "maya", Organization: globex, SessionID: "session-maya"}, acme)
	refused(t, err, `organization "acme"`)

	h.revoke("a", "editor", "maya", "")
	heldIs(t, "maya", h.heldBy(maya, acme), "a:[viewer]")
	h.revoke("a", "viewer", "maya", "")
	heldIs(t, "maya", h.heldBy(maya, acme))
	h.revoke("b", "viewer", "", "team")
	heldIs(t, "tam", h.heldBy(tam, acme), "b:[author]")
	heldIs(t, "tal", h.heldBy(tal, acme))

	h.grantTeam("c", "viewer", "team")
	heldIs(t, "tal", h.heldBy(tal, acme), "c:[viewer]")
	h.store.PutPerson(domain.Person{ID: "tal", Organization: acme})
	heldIs(t, "tal, who left the team", h.heldBy(tal, acme))

	if err := h.svc.Uninstall(h.ctx, h.admin(acme), acme, h.inst(acme, "b").ID); err != nil {
		t.Fatal(err)
	}
	heldIs(t, "tam, b uninstalled", h.heldBy(tam, acme), "c:[viewer]")
}
