package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A person asking for a capability in an organization their session was not
// opened at is refused, naming it — never issued one in the session's own
// organization, which would answer an ask nobody made.
func TestAPersonAskingForAnotherOrganizationIsRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	zoe := h.person("zoe") // globex's administrator, and a user of its solution a
	if _, err := h.svc.GrantRole(h.ctx, zoe, authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "a").ID, Role: "user", PersonID: "zoe"}); err != nil {
		t.Fatal(err)
	}
	read := []*basev0.WorkScopeV1{owned("a.note", h.principal(globex, "a"), []string{"read"})}

	_, err := h.svc.IssueForPerson(h.ctx, zoe, authority.IssueRequest{Audience: "a", Organization: acme, Scopes: read})
	refused(t, err, "a person is issued nothing at "+acme)

	t.Run("through a page as well", func(t *testing.T) {
		_, err := h.svc.IssueForPage(h.ctx, zoe, "a", authority.IssueRequest{Audience: "store", Organization: acme})
		refused(t, err, "a person is issued nothing at "+acme)
	})

	t.Run("naming the session's own organization, or none, is issued there", func(t *testing.T) {
		for _, org := range []string{globex, ""} {
			out, err := h.svc.IssueForPerson(h.ctx, zoe, authority.IssueRequest{Audience: "a", Organization: org, Scopes: read})
			if err != nil {
				t.Fatalf("organization %q: %v", org, err)
			}
			if got := out.Context.GetOrganizationId(); got != globex {
				t.Fatalf("organization %q: issued in %s, not the session's %s", org, got, globex)
			}
		}
	})
}
