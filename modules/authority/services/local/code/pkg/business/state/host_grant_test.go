package state_test

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// A grant the host makes itself (its fixture's, a test's) is decided as every
// other grant is, with the organization's administrator standing as the
// caller: the installation exists and is installed, the role is one its
// target declares, and the subject is one person or one team of its
// organization. The host used to write the row to the store unasked.
func TestAHostGrantIsDecidedAsEveryGrantIs(t *testing.T) {
	k := testkit.New(t)
	wiki := state.InstallationID("acme", "wiki")
	for name, tc := range map[string]struct {
		grant  domain.RoleGrant
		reason string
	}{
		"a role the target does not declare": {domain.RoleGrant{InstallationID: wiki, Role: "owner", PersonID: "bob"}, "declares no role"},
		"a person of another organization":   {domain.RoleGrant{InstallationID: wiki, Role: state.UserRole, PersonID: "omar"}, "not a member of acme"},
		"a person nobody has":                {domain.RoleGrant{InstallationID: wiki, Role: state.UserRole, PersonID: "nobody"}, "not a member of acme"},
		"a team the organization has not":    {domain.RoleGrant{InstallationID: wiki, Role: state.UserRole, TeamID: "no-such-team"}, "not a team of acme"},
		"both a person and a team":           {domain.RoleGrant{InstallationID: wiki, Role: state.UserRole, PersonID: "bob", TeamID: "finance"}, "exactly one"},
		"no subject":                         {domain.RoleGrant{InstallationID: wiki, Role: state.UserRole}, "exactly one"},
		"an installation nobody has":         {domain.RoleGrant{InstallationID: "no-such-installation", Role: state.UserRole, PersonID: "bob"}, "installation"},
	} {
		t.Run(name, func(t *testing.T) {
			err := k.State.GrantRole(tc.grant)
			if err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("the host granted %+v: %v, want a refusal naming %q", tc.grant, err, tc.reason)
			}
			if tc.grant.InstallationID != wiki {
				return
			}
			grants, err := k.State.Service().ListRoleGrants(context.Background(), must(k.State.Caller(signedIn(t, k, "dev-admin"))), "acme", wiki)
			if err != nil {
				t.Fatal(err)
			}
			for _, g := range grants {
				if g.Role == tc.grant.Role && g.PersonID == tc.grant.PersonID && g.TeamID == tc.grant.TeamID {
					t.Fatalf("a refused host grant was written: %+v", g)
				}
			}
		})
	}
	if err := k.State.GrantRole(domain.RoleGrant{InstallationID: wiki, Role: state.UserRole, PersonID: "bob"}); err != nil {
		t.Fatalf("a grant the decision admits: %v", err)
	}
}

func signedIn(t *testing.T, k *testkit.Kit, token string) string {
	t.Helper()
	session, err := k.State.SignIn(token)
	if err != nil {
		t.Fatal(err)
	}
	return session.ID
}
