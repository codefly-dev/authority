package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// A team is proven by the host's team directory, not by a member who happens
// to carry it: a team created a moment ago has nobody in it yet, and its role
// is granted before activation hands anyone access.
func TestARoleIsGrantedToATeamTheDirectoryHolds(t *testing.T) {
	h := newHarness(t)
	h.store.PutTeam(acme, "reviewers") // created inline, no member yet
	h.store.PutTeam(globex, "auditors")
	h.store.PutPerson(domain.Person{ID: "pat", Organization: acme, Teams: []string{"phantom"}}) // a membership with no directory entry
	inst := h.inst(acme, "a").ID
	grant := func(team string) error {
		_, err := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "viewer", TeamID: team})
		return err
	}

	if err := grant("reviewers"); err != nil {
		t.Fatalf("an empty team of the organization is refused: %v", err)
	}
	if _, err := h.svc.GrantRoleAsHost(h.ctx, authority.RoleRequest{Organization: acme, InstallationID: inst, Role: "author", TeamID: "reviewers"}); err != nil {
		t.Fatalf("the host's setup cannot grant an empty team: %v", err)
	}
	if err := grant("team"); err != nil {
		t.Fatalf("a team with members is refused: %v", err)
	}
	if _, err := h.root("tam", "a"); err != nil {
		t.Fatalf("a member of the granted team holds no role: %v", err)
	}
	for name, team := range map[string]string{
		"a team of another organization":           "auditors",
		"a populated team of another organization": "ops",
		"a team nobody created":                    "nobody",
		"a team only a membership names":           "phantom",
	} {
		t.Run(name, func(t *testing.T) {
			err := grant(team)
			refused(t, err, "not a team of")
			code(t, err, domain.Denied)
		})
	}

	// The first member joins after the grant and holds the team's role.
	h.store.PutPerson(domain.Person{ID: "nia", Organization: acme, Teams: []string{"reviewers"}})
	if err := h.svc.PersonChanged(h.ctx, "nia"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.root("nia", "a"); err != nil {
		t.Fatalf("a member who joined the granted team holds no role: %v", err)
	}

	// A grant stays revocable after its team left the directory.
	h.store.DeleteTeam(acme, "reviewers")
	h.revoke("a", "viewer", "", "reviewers")
	if err := grant("reviewers"); err == nil {
		t.Fatal("a deleted team was granted")
	}
}
