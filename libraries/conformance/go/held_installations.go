package conformance

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
)

// heldInstallations is a member's navigation, InstallationService.ListHeld:
// the installations of their organization they hold a role on, granted to
// them or to a team of theirs, with those roles. It answers the caller's own
// holdings alone: holding nothing is an empty list, not a refusal; a revoke
// or leaving the team drops the installation at once; an administrator
// holding no role lists none; another organization's installations never
// appear, and a caller acting at another organization is refused naming it.
//
// The suite makes every grant on A and B itself and first clears the ones it
// reads: the Member's, the TeamMember's and the Admin's, and the Team's. The
// host's own installations beyond A and B may be listed too; only A's and
// B's entries are asserted exactly.
func (sp *principalSuite) heldInstallations(t *testing.T) {
	t.Helper()
	if !sp.c.hasElement("host.installation.v1.InstallationService", "ListHeld") {
		t.Fatal("the published contract lacks host.installation.v1.InstallationService.ListHeld: a member's read of the installations they may use")
	}
	f := sp.f
	A, B := f.A, f.B
	a, b := str(sp.ensure(t, f.Organization, A), "id"), str(sp.ensure(t, f.Organization, B), "id")
	elsewhere := str(sp.ensure(t, f.OtherOrganization, A), "id")
	for _, s := range []SolutionUnderTest{A, B} {
		cleared := map[string]bool{sp.personID(t, f.Member): true, sp.personID(t, f.TeamMember): true, sp.personID(t, f.Admin): true}
		for _, g := range sp.roleGrants(t, f.Admin, f.Organization, s) {
			fields := strings.Fields(g) // "<role> person|team <id>"
			if (fields[1] == "person" && cleared[fields[2]]) || (fields[1] == "team" && fields[2] == f.Team) {
				sp.revoke(t, s, fields[0], map[string]any{fields[1] + "_id": fields[2]})
			}
		}
	}
	// held is what token lists at org of A's and B's installations there, as
	// "<A|B>:<roles>"; every entry it lists is an active installation of org.
	held := func(t *testing.T, token, org string) []string {
		t.Helper()
		out := sp.must(t)(sp.c.call(sp.as(t, token), "host.installation.v1.InstallationService", "ListHeld", map[string]any{"organization_id": org}))
		name := map[string]string{a: "A", b: "B"}
		if org == f.OtherOrganization {
			name = map[string]string{elsewhere: "A"}
		}
		var got []string
		for _, h := range listMsgs(out, "installations") {
			inst := msg(h, "installation")
			if str(inst, "organization_id") != org || enumName(inst, "status") != "STATUS_ACTIVE" || count(h, "roles") == 0 {
				t.Fatalf("%s at %s lists %v: only an active installation of %s they hold a role on belongs there", token, org, h, org)
			}
			if str(inst, "id") == elsewhere && org != f.OtherOrganization {
				t.Fatalf("%s at %s lists another organization's installation %s", token, org, elsewhere)
			}
			if n, ok := name[str(inst, "id")]; ok {
				got = append(got, fmt.Sprintf("%s:%v", n, listStrings(h, "roles")))
			}
		}
		slices.Sort(got)
		return got
	}
	is := func(t *testing.T, who string, got []string, want ...string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Fatalf("%s lists %v of A and B, want %v", who, got, want)
		}
	}

	is(t, "a member holding nothing", held(t, f.Member, f.Organization))
	is(t, "an administrator holding no role", held(t, f.Admin, f.Organization))

	sp.grant(t, A, "viewer", sp.person(t, f.Member))
	sp.grant(t, A, "editor", sp.person(t, f.Member))
	sp.grant(t, B, "author", map[string]any{"team_id": f.Team})
	is(t, "the member granted two roles on A", held(t, f.Member, f.Organization), "A:[editor viewer]")
	is(t, "a member of the team granted author on B", held(t, f.TeamMember, f.Organization), "B:[author]")
	is(t, "the administrator, granting", held(t, f.Admin, f.Organization))

	sp.roleAs(t, f.OtherAdmin, "GrantRole", f.OtherOrganization, A, "viewer", sp.person(t, f.OtherMember))
	is(t, "a member of the other organization", held(t, f.OtherMember, f.OtherOrganization), "A:[viewer]")
	is(t, "the member, beside another organization's grant", held(t, f.Member, f.Organization), "A:[editor viewer]")
	for _, token := range []string{f.OtherMember, f.OtherAdmin} {
		_, err := sp.c.call(sp.as(t, token), "host.installation.v1.InstallationService", "ListHeld", map[string]any{"organization_id": f.Organization})
		refused(t, err, codes.PermissionDenied, fmt.Sprintf("%q", f.Organization))
	}
	sp.roleAs(t, f.OtherAdmin, "RevokeRole", f.OtherOrganization, A, "viewer", sp.person(t, f.OtherMember))

	sp.revoke(t, A, "editor", sp.person(t, f.Member))
	is(t, "the member, editor revoked", held(t, f.Member, f.Organization), "A:[viewer]")
	sp.revoke(t, A, "viewer", sp.person(t, f.Member))
	is(t, "the member, every role revoked", held(t, f.Member, f.Organization))
	sp.revoke(t, B, "author", map[string]any{"team_id": f.Team})
	is(t, "a member of the team, its role revoked", held(t, f.TeamMember, f.Organization))

	// The leaver lists the team's installation until they leave it. Run after
	// the team case, they have already left, and list it no more.
	sp.grant(t, B, "viewer", map[string]any{"team_id": f.Team})
	if slices.Contains(held(t, f.TeamLeaver, f.Organization), "B:[viewer]") {
		if err := f.RemoveFromTeam(sp.ctx, sp.personID(t, f.TeamLeaver), f.Team); err != nil {
			t.Fatal(err)
		}
	}
	is(t, "a person who left the team", held(t, f.TeamLeaver, f.Organization))
	sp.revoke(t, B, "viewer", map[string]any{"team_id": f.Team})
}
