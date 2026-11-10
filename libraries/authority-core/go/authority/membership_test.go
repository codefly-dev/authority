package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A person may belong to several organizations. What they hold, administer
// and may be granted is read from their membership of the organization the
// session was opened at, never from another one.
func TestAPersonOfTwoOrganizationsActsOnlyAsTheMemberOfTheSessions(t *testing.T) {
	h := newHarness(t)
	h.store.PutOrgRole(domain.OrgRole{Organization: globex, Name: "ledger-writer", Scopes: []domain.RoleScope{{Kind: ledgerKind, Actions: []string{"write"}}}})
	h.store.PutOrgRole(domain.OrgRole{Organization: acme, Name: "ledger-plain-reader", Scopes: []domain.RoleScope{{Kind: ledgerKind, Actions: []string{"read"}}}})
	h.store.PutPerson(domain.Person{ID: "pat", Organization: acme, Roles: []string{"ledger-plain-reader"}})
	h.store.PutPerson(domain.Person{ID: "pat", Organization: globex, Roles: []string{"ledger-writer"}})
	// An administrator holds every kind and action of its organization, so the
	// issuance rows above use a person who is not one; administration is pam's.
	h.store.PutPerson(domain.Person{ID: "pam", Organization: acme, Roles: []string{"ledger-plain-reader"}})
	h.store.PutPerson(domain.Person{ID: "pam", Organization: globex, Roles: []string{"admin"}})
	pamAtAcme := authority.Person{ID: "pam", Organization: acme, SessionID: "p-acme"}
	pamAtGlobex := authority.Person{ID: "pam", Organization: globex, SessionID: "p-globex"}
	atAcme := authority.Person{ID: "pat", Organization: acme, SessionID: "s-acme"}
	atGlobex := authority.Person{ID: "pat", Organization: globex, SessionID: "s-globex"}
	read, write := []*basev0.WorkScopeV1{sc(ledgerKind, "read")}, []*basev0.WorkScopeV1{sc(ledgerKind, "write")}

	for _, tc := range []struct {
		name    string
		who     authority.Person
		scopes  []*basev0.WorkScopeV1
		allowed bool
	}{
		{"acme's role at acme", atAcme, read, true},
		{"globex's role does not reach acme", atAcme, write, false},
		{"globex's role at globex", atGlobex, write, true},
		{"acme's role does not reach globex", atGlobex, read, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.IssueForPerson(h.ctx, tc.who, authority.IssueRequest{Audience: "ledger", Scopes: tc.scopes})
			if tc.allowed && err != nil {
				t.Fatal(err)
			}
			if !tc.allowed {
				code(t, err, domain.Denied)
			}
		})
	}

	t.Run("administration is the session organization's", func(t *testing.T) {
		if _, err := h.svc.Installations(h.ctx, pamAtGlobex, globex); err != nil {
			t.Fatal(err)
		}
		_, err := h.svc.Installations(h.ctx, pamAtAcme, globex)
		refused(t, err, "requires an administrator")
		_, err = h.svc.Installations(h.ctx, pamAtAcme, acme)
		refused(t, err, "requires an administrator")
		_, err = h.svc.Review(h.ctx, pamAtAcme, globex, "b")
		refused(t, err, "requires an administrator")
		_, err = h.svc.GrantRole(h.ctx, pamAtAcme, authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, Role: "viewer", PersonID: "pat"})
		refused(t, err, "another organization")
	})

	t.Run("a role granted at one organization's installation counts there alone", func(t *testing.T) {
		h.grant("a", "viewer", "pat")
		if _, err := h.svc.IssueForPerson(h.ctx, atAcme, authority.IssueRequest{Audience: "a"}); err != nil {
			t.Fatal(err)
		}
		_, err := h.svc.IssueForPerson(h.ctx, atGlobex, authority.IssueRequest{Audience: "a"})
		refused(t, err, "holds no role")
	})

	t.Run("a person is granted a role only as a member of the installation's organization", func(t *testing.T) {
		_, err := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "viewer", PersonID: "omar"})
		refused(t, err, "is not a member of")
	})

	t.Run("leaving one organization leaves the other membership standing", func(t *testing.T) {
		h.store.DeleteMember(acme, "pat")
		_, err := h.svc.IssueForPerson(h.ctx, atAcme, authority.IssueRequest{Audience: "ledger", Scopes: read})
		refused(t, err, "no longer a member")
		if _, err := h.svc.IssueForPerson(h.ctx, atGlobex, authority.IssueRequest{Audience: "ledger", Scopes: write}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a session with no organization acts nowhere", func(t *testing.T) {
		_, err := h.svc.Installations(h.ctx, authority.Person{ID: "pat"}, globex)
		refused(t, err, "requires an administrator")
	})
}
