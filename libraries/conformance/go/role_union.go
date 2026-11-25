package conformance

import (
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// A person's roles on an installation are the union of the ones granted to
// them and the ones granted to each team they belong to. These cases hold a
// host to that union as its sources come and go, and each asserts it through
// a capability the member was issued, in two places:
//   - at the callee: Check at the store answers the context the store acts
//     on, carrying exactly the actions the roles still held give (holds);
//   - at the enforcing hop: Check naming a method of the store, as the hop in
//     front of it asks, admits Read only with read and Write only with write.
//
// A capability issued before a source was lost is refused, naming the
// revocation, in both places and when the store asks a hop on it (ended):
// never only when the member asks again.
//
// They use TwoTeamMember alone, a member of Team and SecondTeam; A's user
// role reads the store's kind and its admin role creates, reads and writes.
// They leave neither team a role on A, TwoTeamMember no role and out of
// Team, and SecondTeam deleted.

// holds requires capability, a call through A at the store, to carry exactly
// actions at the store, and to be admitted at the store's methods exactly as
// those actions allow.
func (sp *principalSuite) holds(t *testing.T, capability protoreflect.Message, actions ...string) {
	t.Helper()
	token, U := str(capability, "token"), sp.principal(t, sp.f.Organization, sp.f.A)
	at := sp.c.must(t, sp.ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": sp.f.Store})
	exactOwnedScope(t, msg(at, "context"), sp.f.Kind, actions, U)
	for method, action := range map[string]string{storeReadMethod: "read", storeWriteMethod: "write"} {
		checked, err := sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": token, "audience": sp.f.Store, "method": method})
		if !slices.Contains(actions, action) {
			refused(t, err, codes.PermissionDenied, "requires")
			continue
		}
		if err != nil {
			t.Fatalf("%s is refused to a capability holding %v: %v", method, actions, err)
		}
		exactOwnedScope(t, msg(checked, "context"), sp.f.Kind, actions, U)
	}
}

// ended requires capability, issued before a change, to be refused naming the
// revocation: at the store, at each of its methods, and when the store asks a
// hop on it.
func (sp *principalSuite) ended(t *testing.T, capability protoreflect.Message) {
	t.Helper()
	refused(t, sp.check(capability), codes.PermissionDenied, "revoked")
	for _, method := range []string{storeReadMethod, storeWriteMethod} {
		_, err := sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(capability, "token"), "audience": sp.f.Store, "method": method})
		refused(t, err, codes.PermissionDenied, "revoked")
	}
	_, err := sp.hop(t, capability)
	refused(t, err, codes.PermissionDenied, "revoked")
}

// heldOnA is the roles ListHeld answers the person on A.
func (sp *principalSuite) heldOnA(t *testing.T, as string) []string {
	t.Helper()
	a := str(sp.ensure(t, sp.f.Organization, sp.f.A), "id")
	out := sp.must(t)(sp.c.call(sp.as(t, as), "host.installation.v1.InstallationService", "ListHeld", map[string]any{"organization_id": sp.f.Organization}))
	for _, h := range listMsgs(out, "installations") {
		if str(msg(h, "installation"), "id") == a {
			return slices.Sorted(slices.Values(listStrings(h, "roles")))
		}
	}
	return nil
}

// twoTeams is the fixture these cases need.
func (sp *principalSuite) twoTeams(t *testing.T) (both string, team, second map[string]any) {
	t.Helper()
	f := sp.f
	if f.SecondTeam == "" || f.SecondTeam == f.Team || f.TwoTeamMember == "" {
		t.Fatal("required conformance fixture missing: SecondTeam, another team than Team, and TwoTeamMember, a member of both")
	}
	return f.TwoTeamMember, map[string]any{"team_id": f.Team}, map[string]any{"team_id": f.SecondTeam}
}

// eitherTeamsRole: Team holds user and SecondTeam admin. The member holds the
// union; whichever team's role is revoked, they hold exactly the other's.
func (sp *principalSuite) eitherTeamsRole(t *testing.T) {
	f, A := sp.f, sp.f.A
	both, user, admin := sp.twoTeams(t)
	t.Cleanup(func() { sp.revoke(t, A, "user", user); sp.revoke(t, A, "admin", admin) })
	for _, lost := range []struct {
		name, role string
		team       map[string]any
		kept       string
		left       []string
	}{
		{"the user team's role revoked leaves the admin team's", "user", user, "admin", []string{"create", "read", "write"}},
		{"the admin team's role revoked leaves the user team's", "admin", admin, "user", []string{"read"}},
	} {
		t.Run(lost.name, func(t *testing.T) {
			sp.grant(t, A, "user", user)
			sp.grant(t, A, "admin", admin)
			before := sp.must(t)(sp.through(t, both, A, "store"))
			sp.holds(t, before, "create", "read", "write")
			sp.revokeHeld(t, A, lost.role, lost.team)
			sp.ended(t, before)
			sp.holds(t, sp.must(t)(sp.through(t, both, A, "store")), lost.left...)
			if got := sp.heldOnA(t, both); !slices.Equal(got, []string{lost.kept}) {
				t.Fatalf("after the %s role's team lost it the member holds %v, want %s alone", lost.role, got, lost.kept)
			}
			if lost.kept == "user" {
				_, err := sp.through(t, both, A, "store", sp.owned(f.Kind, []string{"write"}, sp.principal(t, f.Organization, A)))
				refused(t, err, codes.PermissionDenied, "widens")
			}
		})
	}
}

// roleHeldTwice: the member holds user directly and through Team. Losing
// either source keeps the role and ends what was issued before; the role
// ends only with the last source.
func (sp *principalSuite) roleHeldTwice(t *testing.T) {
	f, A := sp.f, sp.f.A
	both, team, _ := sp.twoTeams(t)
	direct := sp.person(t, both)
	t.Cleanup(func() { sp.revoke(t, A, "user", team); sp.revoke(t, A, "user", direct) })
	sp.grant(t, A, "user", direct)
	sp.grant(t, A, "user", team)

	t.Run("the direct grant revoked, the team's stands", func(t *testing.T) {
		before := sp.must(t)(sp.through(t, both, A, "store"))
		sp.holds(t, before, "read")
		sp.revokeHeld(t, A, "user", direct)
		sp.ended(t, before)
		sp.holds(t, sp.must(t)(sp.through(t, both, A, "store")), "read")
		if got := sp.heldOnA(t, both); !slices.Equal(got, []string{"user"}) {
			t.Fatalf("with the team's grant standing the member holds %v, want user", got)
		}
	})
	t.Run("removed from the team, the direct grant stands", func(t *testing.T) {
		sp.grant(t, A, "user", direct)
		before := sp.must(t)(sp.through(t, both, A, "store"))
		sp.holds(t, before, "read")
		sp.removeFromTeam(t, both, f.Team)
		sp.ended(t, before)
		last := sp.must(t)(sp.through(t, both, A, "store"))
		sp.holds(t, last, "read")
		if got := sp.heldOnA(t, both); !slices.Equal(got, []string{"user"}) {
			t.Fatalf("with the direct grant standing the member holds %v, want user", got)
		}
		// The team's grant still stands and is theirs no more: the direct
		// grant is now the only source, and revoking it ends the role.
		sp.revokeHeld(t, A, "user", direct)
		sp.ended(t, last)
		_, err := sp.root(t, both, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
	})
}

// teamDeleted: SecondTeam holds admin and the host deletes the team
// (DeleteTeam, the host's own path).
func (sp *principalSuite) teamDeleted(t *testing.T) {
	f, A := sp.f, sp.f.A
	both, _, second := sp.twoTeams(t)
	if f.DeleteTeam == nil {
		t.Fatal("required conformance fixture missing: DeleteTeam, the host deleting a team")
	}
	sp.grant(t, A, "admin", second)
	before := sp.must(t)(sp.through(t, both, A, "store"))
	sp.holds(t, before, "create", "read", "write")
	as, err := sp.cast(t, both, f.SecondTeam)
	if err != nil {
		t.Fatalf("a member casts onto their own team: %v", err)
	}
	asTeam := sp.must(t)(sp.through(t, as, A, "store"))
	sp.holds(t, asTeam, "create", "read", "write")

	if err := f.DeleteTeam(sp.ctx, f.SecondTeam); err != nil {
		t.Fatal(err)
	}

	sp.ended(t, before)
	for _, method := range []string{"", storeReadMethod, storeWriteMethod} {
		request := map[string]any{"token": str(asTeam, "token"), "audience": f.Store}
		if method != "" {
			request["method"] = method
		}
		_, err := sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "Check", request)
		refused(t, err, codes.PermissionDenied, "")
	}
	_, err = sp.root(t, both, A)
	refused(t, err, codes.PermissionDenied, "holds no role")
	_, err = sp.through(t, as, A, "store")
	refused(t, err, codes.PermissionDenied, "")
	if _, err = sp.cast(t, both, f.SecondTeam); err == nil {
		t.Fatal("a deleted team is cast onto")
	}
	if got := sp.castable(t, both); got[f.SecondTeam] != nil {
		t.Fatalf("a deleted team is still offered to act as: %v", got)
	}
	if got := sp.heldOnA(t, both); len(got) != 0 {
		t.Fatalf("after their team was deleted the member holds %v on the installation, want nothing", got)
	}
	_, err = sp.c.call(sp.as(t, f.Admin), "host.installation.v1.InstallationService", "GrantRole", map[string]any{
		"organization_id": f.Organization, "installation_id": str(sp.ensure(t, f.Organization, A), "id"), "role": "user", "team_id": f.SecondTeam})
	refused(t, err, codes.PermissionDenied, "not a team of")
	sp.revokeHeld(t, A, "admin", second)
}
