package conformance

import (
	"testing"

	"google.golang.org/grpc/codes"
)

// teamRemoval is the host removing a member from a team (RemoveFromTeam, the
// host's own path: the interface has none). The authority reads a person's
// teams from the host and is told nothing of a removal unless the host tells
// it, so the suite holds the host to the result, by the next call:
//   - every capability the member was issued through the team's role is
//     refused by Check, naming the revocation: their call through A, and the
//     store's own hop on it, which is sealed to the store's installation, not
//     to the one the team's role is on;
//   - ListResources answers such a capability nothing, refusing it;
//   - a fresh ask at A is refused "holds no role";
//   - acting as the team is refused: the session they had cast onto it issues
//     nothing more and what it was issued is refused; a new cast is refused,
//     naming that they could not grant the team's roles; ListCastableTeams
//     offers them the team no more;
//   - what only the team gave is all they lose: the role granted to them
//     directly on B is issued again, and another member of the team is
//     untouched.
//
// It runs with Team holding user on A, and leaves it so.
func (sp *principalSuite) teamRemoval(t *testing.T) {
	t.Helper()
	f := sp.f
	A, B, leaver := f.A, f.B, f.TeamLeaver
	sp.grant(t, B, "user", sp.person(t, leaver))
	defer sp.revoke(t, B, "user", sp.person(t, leaver))

	through := sp.must(t)(sp.through(t, leaver, A, "store"))
	deeper := sp.must(t)(sp.hop(t, through))
	if sealed, role := str(msg(msg(deeper, "context"), "seal"), "installation_id"), str(sp.ensure(t, f.Organization, A), "id"); sealed == role {
		t.Fatalf("the store's hop is sealed to %s, the installation the team's role is on: it proves nothing of a capability sealed elsewhere", sealed)
	}
	own := sp.must(t)(sp.through(t, leaver, B, "store"))
	as, err := sp.cast(t, leaver, f.Team)
	if err != nil {
		t.Fatalf("a member must be able to act as their team: %v", err)
	}
	asTeam := sp.must(t)(sp.through(t, as, A, "store"))
	for name, capability := range map[string]error{"the call through the team's role": sp.check(through), "the store's hop on it": sp.check(deeper),
		"the call through their own role": sp.check(own), "the call made as the team": sp.check(asTeam)} {
		if capability != nil {
			t.Fatalf("%s is refused while they are a member: %v", name, capability)
		}
	}

	if err := f.RemoveFromTeam(sp.ctx, sp.personID(t, leaver), f.Team); err != nil {
		t.Fatal(err)
	}

	refused(t, sp.check(through), codes.PermissionDenied, "revoked")
	refused(t, sp.check(deeper), codes.PermissionDenied, "revoked")
	refused(t, sp.check(asTeam), codes.PermissionDenied, "")
	_, err = sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{"token": str(through, "token"), "audience": f.Store, "resource_kind": f.Kind, "action": "read"})
	refused(t, err, codes.PermissionDenied, "revoked")
	_, err = sp.root(t, leaver, A)
	refused(t, err, codes.PermissionDenied, "holds no role")

	_, err = sp.through(t, as, A, "store")
	refused(t, err, codes.PermissionDenied, "")
	_, err = sp.cast(t, leaver, f.Team)
	refused(t, err, codes.PermissionDenied, "could not grant")
	if got := sp.castable(t, leaver); got[f.Team] != nil {
		t.Fatalf("a person removed from the team is still offered it to act as: %v", got)
	}

	exactOwnedScope(t, msg(sp.must(t)(sp.through(t, leaver, B, "store")), "context"), f.Kind, []string{"read"}, sp.principal(t, f.Organization, B))
	exactOwnedScope(t, msg(sp.must(t)(sp.through(t, f.TeamMember, A, "store")), "context"), f.Kind, []string{"read"}, sp.principal(t, f.Organization, A))
}
