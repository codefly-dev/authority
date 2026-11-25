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
	t.Parallel()
	h := newHarness(t)
	// pat is a member of both: a user of solution a at acme, an admin of
	// solution b at globex. Each role is held on one organization's
	// installation and counts there alone.
	h.store.PutPerson(domain.Person{ID: "pat", Organization: acme})
	h.store.PutPerson(domain.Person{ID: "pat", Organization: globex})
	h.install(globex, "b")
	h.grant("a", "user", "pat")
	if _, err := h.svc.GrantRole(h.ctx, h.person("zoe"), authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "b").ID, Role: "admin", PersonID: "pat"}); err != nil {
		t.Fatal(err)
	}
	// Administration is pam's, at globex alone.
	h.store.PutPerson(domain.Person{ID: "pam", Organization: acme})
	h.store.PutPerson(domain.Person{ID: "pam", Organization: globex, Roles: []string{"admin"}})
	pamAtAcme := authority.Person{ID: "pam", Organization: acme, SessionID: "p-acme"}
	pamAtGlobex := authority.Person{ID: "pam", Organization: globex, SessionID: "p-globex"}
	atAcme := authority.Person{ID: "pat", Organization: acme, SessionID: "s-acme"}
	atGlobex := authority.Person{ID: "pat", Organization: globex, SessionID: "s-globex"}
	read := []*basev0.WorkScopeV1{owned("a.note", h.principal(acme, "a"), []string{"read"})}
	write := []*basev0.WorkScopeV1{owned("b.note", h.principal(globex, "b"), []string{"write"})}

	for _, tc := range []struct {
		name     string
		who      authority.Person
		audience string
		scopes   []*basev0.WorkScopeV1
		allowed  bool
	}{
		{"acme's role at acme", atAcme, "a", read, true},
		{"globex's role does not reach acme", atAcme, "b", nil, false},
		{"globex's role at globex", atGlobex, "b", write, true},
		{"acme's role does not reach globex", atGlobex, "a", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.svc.IssueForPerson(h.ctx, tc.who, authority.IssueRequest{Audience: tc.audience, Scopes: tc.scopes})
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
		_, err = h.svc.GrantRole(h.ctx, pamAtAcme, authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, Role: "user", PersonID: "pat"})
		refused(t, err, "another organization")
	})

	t.Run("a role granted at one organization's installation counts there alone", func(t *testing.T) {
		if _, err := h.svc.IssueForPerson(h.ctx, atAcme, authority.IssueRequest{Audience: "a"}); err != nil {
			t.Fatal(err)
		}
		_, err := h.svc.IssueForPerson(h.ctx, atGlobex, authority.IssueRequest{Audience: "a"})
		refused(t, err, "holds no role")
	})

	t.Run("a person is granted a role only as a member of the installation's organization", func(t *testing.T) {
		_, err := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "user", PersonID: "omar"})
		refused(t, err, "is not a member of")
	})

	t.Run("leaving one organization leaves the other membership standing", func(t *testing.T) {
		h.store.DeleteMember(acme, "pat")
		_, err := h.svc.IssueForPerson(h.ctx, atAcme, authority.IssueRequest{Audience: "a", Scopes: read})
		refused(t, err, "no longer a member")
		if _, err := h.svc.IssueForPerson(h.ctx, atGlobex, authority.IssueRequest{Audience: "b", Scopes: write}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a session with no organization acts nowhere", func(t *testing.T) {
		_, err := h.svc.Installations(h.ctx, authority.Person{ID: "pat"}, globex)
		refused(t, err, "requires an administrator")
	})
}
