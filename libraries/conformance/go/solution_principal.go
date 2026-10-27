package conformance

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SolutionPrincipalCase is the TARGET contract for solution identity; no host
// passes it yet.
//
// An installed solution is a principal of its organization (U), with a stable
// UUID like a person's: one per (organization, solution), reused by a
// reinstall, disabled by an uninstall. The installation acting for itself IS
// U, holding the role its install request names; nobody else inherits that
// role, the installing person included. The solution's declared roles are
// permission levels on U's data, and role names carry no rank: what a role
// may do is the scopes it declares. Granting a person or a team a role
// (GrantRole) is the access, revoking it (RevokeRole) ends it at once, both
// idempotent, and ListRoleGrants answers who holds which. A new grant leaves
// every existing capability valid; only a revoke, leaving a team or the
// organization, an uninstall or a withdrawn owner_aware invalidates, and that
// is permanent: only fresh capabilities work afterwards. An uninstall clears
// the installation's role grants, so a reinstall needs re-grants. An
// administrator of the installation's organization, or a holder of the
// installer role on that installation, grants, revokes and lists; nobody
// else, and a request naming an installation of another organization is
// refused naming the organization.
//
// A capability issued through the solution, to a person or to U itself, is
// CONFINED to U's data: owner-selected scopes {kind, actions,
// resource_owner_id: U} from the solution's roles alone; a person's own
// organization grants never flow in (they reach solution code only through an
// explicitly declared binding, under rule A). A scope naming an owner and ids
// admits a resource only when both match. Every audience receiving
// owner-selected scopes, solutions included, declares owner-aware checking
// (AuthorityManifestV1.owner_aware); the authority refuses the rest, and a
// delivery withdrawing it refuses the owner-selected capabilities issued
// before. Check with a method admits an owner-selected scope by kind and
// action; the module then enforces owner == the resource's owner
// (Claims.AllowsOwned and its Python and TypeScript twins).
//
// An existing resource joins U only by AuthorizeTransfer: the store (the
// kind's serving module) asks, attesting the resource exists and who owns it
// now. The authority allows it when the current owner is the organization or
// a person of it (never another solution principal, another organization,
// its people or an unknown owner), the person holds admin on THAT resource
// from their own organization grants, and the person's current roles on U
// hold write on the kind. All are read live, not from the capability. The
// store then records U as owner; the original creator stays the author; the
// previous owner keeps nothing through ownership; organization grants, which
// name resources and not owners, are unaffected.
//
// The suite delivers A, B, C (a solution not declaring owner_aware), Store
// and LegacyStore, installs A, B and C, and makes every grant itself. The host
// supplies, at Organization unless stated:
//   - Admin: an organization administrator (whatever its own grants on Kind).
//   - Viewer, Editor, Member, Installer, TeamMember, TeamLeaver, OrgLeaver:
//     members with no role on A, B or C but what the suite grants; TeamMember
//     and TeamLeaver belong to Team.
//   - Administrator holds admin, and Reader holds read, on Existing from their
//     own organization grants at Store, and nothing else of Kind.
//   - NoteReader holds read on A's own kind ("<A>.note") from their own
//     organization grants.
//   - OtherAdmin and OtherMember: an administrator and a member of
//     OtherOrganization; OtherTeam: a team of OtherOrganization.
//   - Existing: a resource of Kind owned by Organization.
//   - Uninstall, RemoveFromTeam, RemoveFromOrganization: the host's own paths
//     (the interface has none). Install must converge for the suite's solutions.
type SolutionPrincipalCase struct {
	Organization, OtherOrganization                string
	A, B, C                                        SolutionUnderTest
	Store, StoreCredential, Kind                   string
	LegacyStore, LegacyStoreCredential, LegacyKind string
	Generation                                     uint64
	Admin, Viewer, Editor, Member, Installer       string
	Team, TeamMember, TeamLeaver, OrgLeaver        string
	Administrator, Reader, NoteReader              string
	OtherAdmin, OtherMember, OtherTeam             string
	Existing                                       string
	Uninstall                                      func(ctx context.Context, installationID string) error
	RemoveFromTeam                                 func(ctx context.Context, personID, team string) error
	RemoveFromOrganization                         func(ctx context.Context, personID string) error
	SignManifest, SignAuthority                    func(document []byte) ([]byte, error)
	DeliveryCredential                             func(module string) string
	// InstallModule is Fixture.InstallModule, for the modules this suite delivers.
	InstallModule              func(ctx context.Context, module string) error
	HostCoordinate, HostDomain string
}

// SolutionUnderTest is one solution the suite delivers and installs.
type SolutionUnderTest struct {
	Solution, Credential string
}

// solutionPrincipalContract is what the target adds; solutionPrincipalRemoved
// is what it deletes (one mechanism per job). Both are checked first.
var solutionPrincipalContract = []struct{ message, element string }{
	{"host.installation.v1.Installation", "principal_id"},
	{"host.installation.v1.Installation", "roles"},
	{"host.installation.v1.InstallationService", "GrantRole"},
	{"host.installation.v1.InstallationService", "RevokeRole"},
	{"host.installation.v1.InstallationService", "ListRoleGrants"},
	{"host.installation.v1.GrantRoleRequest", "organization_id"},
	{"host.installation.v1.GrantRoleRequest", "installation_id"},
	{"host.installation.v1.GrantRoleRequest", "role"},
	{"host.installation.v1.GrantRoleRequest", "person_id"},
	{"host.installation.v1.GrantRoleRequest", "team_id"},
	{"host.installation.v1.RevokeRoleRequest", "organization_id"},
	{"host.installation.v1.RevokeRoleRequest", "installation_id"},
	{"host.installation.v1.RevokeRoleRequest", "role"},
	{"host.installation.v1.RevokeRoleRequest", "person_id"},
	{"host.installation.v1.RevokeRoleRequest", "team_id"},
	{"host.installation.v1.ListRoleGrantsRequest", "organization_id"},
	{"host.installation.v1.ListRoleGrantsRequest", "installation_id"},
	{"host.installation.v1.ListRoleGrantsResponse", "grants"},
	{"host.installation.v1.RoleGrant", "role"},
	{"host.installation.v1.RoleGrant", "person_id"},
	{"host.installation.v1.RoleGrant", "team_id"},
	{"host.authority.v1.WorkScopeV1", "resource_owner_id"},
	{"host.authority.v1.ResourceGrant", "resource_owner_id"},
	{"host.authority.v1.AuthorityService", "AuthorizeTransfer"},
	{"host.authority.v1.AuthorizeTransferRequest", "token"},
	{"host.authority.v1.AuthorizeTransferRequest", "actor"},
	{"host.authority.v1.AuthorizeTransferRequest", "resource_kind"},
	{"host.authority.v1.AuthorizeTransferRequest", "resource_id"},
	{"host.authority.v1.AuthorizeTransferRequest", "from_owner_id"},
	{"host.authority.v1.AuthorizeTransferRequest", "to_principal_id"},
	{"host.authority.v1.AuthorizeTransferResponse", "principal_id"},
	{"host.authority.v1.AuthorizeTransferResponse", "authorized_by"},
	{"host.composition.v1.AuthorityManifestV1", "owner_aware"},
}

var solutionPrincipalRemoved = []struct{ message, element string }{
	{"host.installation.v1.InstallationService", "GrantToTeam"},
	{"host.installation.v1.GrantToTeamRequest", ""},
	{"host.installation.v1.Installation", "team_ids"},
	{"host.installation.v1.Installation", "agent_principal_id"},
}

var principalUUID = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RunSolutionPrincipalTarget drives the target over one connection. It is not
// part of Run until a host implements it. It supersedes Run's cases that
// encode the earlier model; those now assert this model whenever the
// published contract is the target's (client.solutionPrincipal), so one host
// passes both. See the README for the list.
func RunSolutionPrincipalTarget(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f SolutionPrincipalCase) {
	t.Helper()
	c, err := newClient(conn, descriptors)
	if err != nil {
		t.Fatalf("conformance: %v", err)
	}
	if problems := c.contractProblems(); len(problems) > 0 {
		t.Fatalf("target: the published contract %s", strings.Join(problems, "; "))
	}
	if f.Uninstall == nil || f.RemoveFromTeam == nil || f.RemoveFromOrganization == nil || f.SignManifest == nil || f.SignAuthority == nil ||
		f.DeliveryCredential == nil || f.Existing == "" || f.OtherOrganization == "" || f.LegacyStore == "" || f.Team == "" || f.OtherTeam == "" || f.C.Solution == "" ||
		slices.Contains([]string{f.Admin, f.Viewer, f.Editor, f.Member, f.Installer, f.TeamMember, f.TeamLeaver, f.OrgLeaver, f.Administrator, f.Reader, f.NoteReader, f.OtherAdmin, f.OtherMember}, "") {
		t.Fatal("required conformance fixture missing: solution principal case")
	}
	ctx := context.Background()
	sp := &principalSuite{c: c, f: f, ctx: ctx, sessions: map[string]protoreflect.Message{}, installed: map[string]protoreflect.Message{}, storeGeneration: f.Generation}
	sp.deliverAll(t)
	A, B, C := f.A, f.B, f.C
	U := func(t *testing.T) string { return sp.principal(t, f.Organization, A) }
	V := func(t *testing.T) string { return sp.principal(t, f.Organization, B) }
	// Asks no capability through A may carry, by a person or by U itself.
	widening := func(t *testing.T) map[string]any {
		return map[string]any{
			"another installation's principal": sp.owned(f.Kind, []string{"read"}, V(t)),
			"another principal's ids":          sp.owned(f.Kind, []string{"read"}, V(t), "u-doc"),
			"another organization's principal": sp.owned(f.Kind, []string{"read"}, sp.principal(t, f.OtherOrganization, A)),
			"the whole kind":                   scopeAsk(f.Kind, []string{"read"}, nil),
			"a resource by id alone":           scopeAsk(f.Kind, []string{"read"}, []string{f.Existing}),
			"a person as owner":                sp.owned(f.Kind, []string{"read"}, sp.personID(t, f.Viewer)),
			"the installation id as owner":     sp.owned(f.Kind, []string{"read"}, str(sp.ensure(t, f.Organization, A), "id")),
			"the organization as owner":        sp.owned(f.Kind, []string{"read"}, f.Organization),
		}
	}

	t.Run("install creates the solution principal and its roles; a reinstall keeps its UUID; another organization's is another principal", func(t *testing.T) {
		a, b := sp.ensure(t, f.Organization, A), sp.ensure(t, f.Organization, B)
		for _, inst := range []protoreflect.Message{a, b} {
			if id := str(inst, "principal_id"); !principalUUID.MatchString(id) || id == str(inst, "id") {
				t.Fatalf("principal_id %q is not a principal UUID of its own", id)
			}
			if got := slices.Sorted(slices.Values(listStrings(inst, "roles"))); !slices.Equal(got, []string{"author", "editor", "installer", "viewer"}) {
				t.Fatalf("the installation's roles are %v, want the solution's declared roles", got)
			}
		}
		if U(t) == V(t) {
			t.Fatal("two installations share a principal")
		}
		if other := sp.principal(t, f.OtherOrganization, A); other == U(t) {
			t.Fatal("one solution installed in two organizations shares a principal")
		}
		before := U(t)
		sp.uninstall(t, f.Organization, A)
		if after := U(t); after != before {
			t.Fatalf("a reinstall made principal %s, want %s: its data would be orphaned", after, before)
		}
	})
	t.Run("the install request's role is the agent's, and no person's; the agent is confined to the principal's data", func(t *testing.T) {
		byAgent := sp.must(t)(sp.agent(t, A, "store"))
		wc := msg(byAgent, "context")
		exactOwnedScope(t, wc, f.Kind, []string{"create", "read", "write"}, U(t))
		if str(wc, "owner_principal_kind") != "agent" || str(wc, "owner_principal_id") != U(t) {
			t.Fatalf("the installation acting for itself is %s (%s), want the solution principal %s", str(wc, "owner_principal_id"), str(wc, "owner_principal_kind"), U(t))
		}
		_, err := sp.agent(t, A, "store", sp.owned(f.Kind, []string{"admin"}, U(t)))
		refused(t, err, codes.PermissionDenied, "beyond")
		_, err = sp.agent(t, A, "")
		refused(t, err, codes.PermissionDenied, "binding")
		for name, ask := range widening(t) {
			_, err := sp.agent(t, A, "store", ask)
			t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
		}
		_, err = sp.root(t, f.Admin, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		if got := sp.roleGrants(t, f.Admin, f.Organization, A); slices.ContainsFunc(got, func(g string) bool { return strings.HasSuffix(g, " person "+sp.personID(t, f.Admin)) }) {
			t.Fatalf("the installing person holds a role: %v", got)
		}
	})
	t.Run("without a role on the solution a person is refused, naming the reason", func(t *testing.T) {
		_, err := sp.root(t, f.Member, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
	})
	t.Run("a viewer reads exactly what the principal owns, and nothing a person, an installation or another principal owns", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		root := sp.must(t)(sp.root(t, f.Viewer, A))
		exactOwnedScope(t, msg(root, "context"), A.Solution+".note", []string{"read"}, U(t))
		out := sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, U(t))
		sp.listed(t, out, f.Kind, "read", map[string]string{"*": U(t)})
		narrowed := sp.must(t)(sp.through(t, f.Viewer, A, "store", sp.owned(f.Kind, []string{"read"}, U(t), "u-doc")))
		exactOwnedScopeIDs(t, msg(narrowed, "context"), f.Kind, []string{"read"}, U(t), []string{"u-doc"})
		sp.listed(t, narrowed, f.Kind, "read", map[string]string{"u-doc": U(t)})
		for name, ask := range widening(t) {
			_, err := sp.through(t, f.Viewer, A, "store", ask)
			t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
		}
	})
	t.Run("a route requiring the kind admits an owner-selected scope; the module enforces the owner", func(t *testing.T) {
		// The method gate is coarse (kind and action); the checked context
		// names the owner, which the module compares with the resource's owner
		// (the library targets pin AllowsOwned refusing another owner).
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		out := sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		checked := c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Store, "method": storeReadMethod})
		exactOwnedScope(t, msg(checked, "context"), f.Kind, []string{"read"}, U(t))
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Store, "method": storeWriteMethod})
		refused(t, err, codes.PermissionDenied, "requires")
	})
	t.Run("a capability through the solution is confined to the principal's data; the person's own grants never flow in", func(t *testing.T) {
		for _, token := range []string{f.Reader, f.Administrator} {
			sp.grant(t, A, "viewer", sp.person(t, token))
			out := sp.must(t)(sp.through(t, token, A, "store"))
			exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, U(t))
		}
		_, err := sp.through(t, f.Reader, A, "store", scopeAsk(f.Kind, []string{"read"}, []string{f.Existing}))
		refused(t, err, codes.PermissionDenied, "confined")
		_, err = sp.through(t, f.Administrator, A, "store", scopeAsk(f.Kind, []string{"admin"}, []string{f.Existing}))
		refused(t, err, codes.PermissionDenied, "confined")
		// At the solution's own kind too: an organization grant on it stays out.
		sp.grant(t, A, "viewer", sp.person(t, f.NoteReader))
		exactOwnedScope(t, msg(sp.must(t)(sp.root(t, f.NoteReader, A)), "context"), A.Solution+".note", []string{"read"}, U(t))
	})
	t.Run("every audience receiving owner-selected scopes declares owner-aware checking, solutions included", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		_, err := sp.through(t, f.Viewer, A, "legacy")
		refused(t, err, codes.PermissionDenied, "owner-aware")
		_, err = sp.agent(t, A, "legacy")
		refused(t, err, codes.PermissionDenied, "owner-aware")
		sp.grant(t, C, "viewer", sp.person(t, f.Viewer))
		_, err = sp.root(t, f.Viewer, C)
		refused(t, err, codes.PermissionDenied, "owner-aware")
		// A module's hop counts as much as a solution's: the store carrying
		// owner-selected scopes on to the legacy store is refused.
		atStore := sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		_, err = sp.hopTo(t, atStore, "legacy", f.LegacyStore)
		refused(t, err, codes.PermissionDenied, "owner-aware")
	})
	t.Run("withdrawing owner-aware checking refuses the owner-selected capabilities issued before", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		before := sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		sp.deliverStore(t, false)
		refused(t, sp.check(before), codes.PermissionDenied, "owner-aware")
		// Re-declaring it revives nothing: only fresh capabilities work.
		sp.deliverStore(t, true)
		refused(t, sp.check(before), codes.PermissionDenied, "owner-aware")
		sp.must(t)(sp.through(t, f.Viewer, A, "store"))
	})
	t.Run("a resource created through the solution is owned by its principal, the person its author", func(t *testing.T) {
		sp.grant(t, A, "author", sp.person(t, f.Editor))
		out := sp.must(t)(sp.through(t, f.Editor, A, "store", sp.owned(f.Kind, []string{"create"}, U(t))))
		wc := msg(out, "context")
		exactOwnedScope(t, wc, f.Kind, []string{"create"}, U(t))
		if str(wc, "owner_principal_id") != sp.personID(t, f.Editor) || str(wc, "owner_principal_kind") != "human" {
			t.Fatalf("the author is %s (%s), want the person", str(wc, "owner_principal_id"), str(wc, "owner_principal_kind"))
		}
		byAgent := sp.must(t)(sp.agent(t, A, "store", sp.owned(f.Kind, []string{"create"}, U(t))))
		exactOwnedScope(t, msg(byAgent, "context"), f.Kind, []string{"create"}, U(t))
	})
	t.Run("a role writes when its scopes hold write, whatever it is called; a viewer cannot", func(t *testing.T) {
		sp.grant(t, A, "author", sp.person(t, f.Editor))
		sp.grant(t, A, "editor", sp.person(t, f.Member))
		out := sp.must(t)(sp.through(t, f.Editor, A, "store", sp.owned(f.Kind, []string{"write"}, U(t))))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"write"}, U(t))
		// "editor" here declares read only: a name grants nothing.
		_, err := sp.through(t, f.Member, A, "store", sp.owned(f.Kind, []string{"write"}, U(t)))
		refused(t, err, codes.PermissionDenied, "widens")
		sp.revoke(t, A, "editor", sp.person(t, f.Member))
	})
	t.Run("an administrator of the organization or the installation's installer grants, revokes and lists; anyone else, and every malformed grant, is refused by name", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "installer", sp.person(t, f.Installer))
		// Grants are idempotent: twice is one row.
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		if n := countOf(sp.roleGrants(t, f.Admin, f.Organization, A), "viewer person "+sp.personID(t, f.Viewer)); n != 1 {
			t.Fatalf("a repeated grant is listed %d times", n)
		}
		sp.roleAs(t, f.Installer, "GrantRole", f.Organization, A, "viewer", sp.person(t, f.Member))
		sp.roleAs(t, f.Installer, "RevokeRole", f.Organization, A, "viewer", sp.person(t, f.Member))
		sp.roleGrants(t, f.Installer, f.Organization, A)
		instA, instB := str(sp.ensure(t, f.Organization, A), "id"), str(sp.ensure(t, f.Organization, B), "id")
		instElsewhere := str(sp.ensure(t, f.OtherOrganization, A), "id")
		grant := func(installation, role string, subject map[string]any) map[string]any {
			out := map[string]any{"organization_id": f.Organization, "installation_id": installation, "role": role}
			for k, v := range subject {
				out[k] = v
			}
			return out
		}
		member := map[string]any{"person_id": sp.personID(t, f.Member)}
		for name, r := range map[string]struct {
			caller, method string
			fields         map[string]any
			code           codes.Code
			reason         string
		}{
			"a viewer granting itself installer": {f.Viewer, "GrantRole", grant(instA, "installer", sp.person(t, f.Viewer)), codes.PermissionDenied, "belongs to another organization"},
			"a viewer revoking the installer":    {f.Viewer, "RevokeRole", grant(instA, "installer", sp.person(t, f.Installer)), codes.PermissionDenied, "belongs to another organization"},
			"a viewer listing grants":            {f.Viewer, "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": instA}, codes.PermissionDenied, "belongs to another organization"},
			// A caller of another organization learns nothing of this one: the
			// installation answers as an absent one would (r143 M-a).
			"another organization's administrator granting":        {f.OtherAdmin, "GrantRole", grant(instA, "viewer", member), codes.PermissionDenied, "belongs to another organization"},
			"another organization's administrator revoking":        {f.OtherAdmin, "RevokeRole", grant(instA, "viewer", sp.person(t, f.Viewer)), codes.PermissionDenied, "belongs to another organization"},
			"another organization's administrator listing":         {f.OtherAdmin, "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": instA}, codes.PermissionDenied, "belongs to another organization"},
			"A's installer granting on B":                          {f.Installer, "GrantRole", grant(instB, "author", sp.person(t, f.Installer)), codes.PermissionDenied, "belongs to another organization"},
			"A's installer revoking on B":                          {f.Installer, "RevokeRole", grant(instB, "viewer", member), codes.PermissionDenied, "belongs to another organization"},
			"another organization's id":                            {f.Admin, "GrantRole", map[string]any{"organization_id": f.OtherOrganization, "installation_id": instA, "role": "viewer", "person_id": sp.personID(t, f.Member)}, codes.PermissionDenied, "organization"},
			"granting on another organization's installation":      {f.Admin, "GrantRole", grant(instElsewhere, "viewer", member), codes.PermissionDenied, "organization"},
			"revoking on another organization's installation":      {f.Admin, "RevokeRole", grant(instElsewhere, "viewer", sp.person(t, f.OtherMember)), codes.PermissionDenied, "organization"},
			"listing another organization's installation":          {f.Admin, "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": instElsewhere}, codes.PermissionDenied, "organization"},
			"the installer on another organization's installation": {f.Installer, "GrantRole", grant(instElsewhere, "viewer", member), codes.PermissionDenied, "organization"},
			"an undeclared role":                                   {f.Admin, "GrantRole", grant(instA, "owner", member), codes.NotFound, "declares no role"},
			"both a person and a team":                             {f.Admin, "GrantRole", grant(instA, "viewer", map[string]any{"person_id": sp.personID(t, f.Member), "team_id": f.Team}), codes.InvalidArgument, "exactly one"},
			"neither a person nor a team":                          {f.Admin, "GrantRole", grant(instA, "viewer", nil), codes.InvalidArgument, "exactly one"},
			"a person of another organization":                     {f.Admin, "GrantRole", grant(instA, "viewer", sp.person(t, f.OtherMember)), codes.PermissionDenied, "not a member"},
			"a team of another organization":                       {f.Admin, "GrantRole", grant(instA, "viewer", map[string]any{"team_id": f.OtherTeam}), codes.PermissionDenied, "not a team of"},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := c.call(sp.as(t, r.caller), "host.installation.v1.InstallationService", r.method, r.fields)
				refused(t, err, r.code, r.reason)
			})
		}
	})
	t.Run("another installation's and another organization's members never reach the principal's data", func(t *testing.T) {
		sp.grant(t, B, "viewer", sp.person(t, f.Member))
		_, err := sp.root(t, f.Member, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		out := sp.must(t)(sp.through(t, f.Member, B, "store"))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, V(t))
		_, err = sp.through(t, f.Member, B, "store", sp.owned(f.Kind, []string{"read"}, U(t)))
		refused(t, err, codes.PermissionDenied, "widens")
		other := sp.principal(t, f.OtherOrganization, A)
		sp.roleAs(t, f.OtherAdmin, "GrantRole", f.OtherOrganization, A, "viewer", sp.person(t, f.OtherMember))
		elsewhere := sp.must(t)(sp.through(t, f.OtherMember, A, "store"))
		exactOwnedScope(t, msg(elsewhere, "context"), f.Kind, []string{"read"}, other)
		_, err = sp.through(t, f.OtherMember, A, "store", sp.owned(f.Kind, []string{"read"}, U(t)))
		refused(t, err, codes.PermissionDenied, "widens")
	})
	t.Run("a child never widens the owner, the actions or the ids it narrowed to", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "author", sp.person(t, f.Editor))
		narrowed := sp.must(t)(sp.through(t, f.Viewer, A, "store", sp.owned(f.Kind, []string{"read"}, U(t))))
		exactOwnedScope(t, msg(sp.must(t)(sp.hop(t, narrowed)), "context"), f.Kind, []string{"read"}, U(t))
		readOnly := sp.must(t)(sp.through(t, f.Editor, A, "store", sp.owned(f.Kind, []string{"read"}, U(t))))
		oneDoc := sp.must(t)(sp.through(t, f.Viewer, A, "store", sp.owned(f.Kind, []string{"read"}, U(t), "u-doc")))
		exactOwnedScopeIDs(t, msg(sp.must(t)(sp.hop(t, oneDoc)), "context"), f.Kind, []string{"read"}, U(t), []string{"u-doc"})
		for name, attempt := range map[string]struct {
			parent protoreflect.Message
			ask    any
		}{
			"another owner":          {narrowed, sp.owned(f.Kind, []string{"read"}, V(t))},
			"the whole kind":         {narrowed, scopeAsk(f.Kind, []string{"read"}, nil)},
			"an action it dropped":   {readOnly, sp.owned(f.Kind, []string{"write"}, U(t))},
			"the ids it narrowed to": {oneDoc, sp.owned(f.Kind, []string{"read"}, U(t))},
		} {
			_, err := sp.hop(t, attempt.parent, attempt.ask)
			t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
		}
	})
	t.Run("an existing resource joins the principal only by a transfer from the organization or its person, administered on that resource through the person's own grants, by a holder of write on the principal's data", func(t *testing.T) {
		sp.revoke(t, A, "author", sp.person(t, f.Administrator))
		sp.grant(t, A, "editor", sp.person(t, f.Administrator))
		asEditorInName := sp.must(t)(sp.through(t, f.Administrator, A, "store"))
		_, err := sp.transfer(t, asEditorInName, f.StoreCredential, f.Existing, f.Organization, U(t))
		refused(t, err, codes.PermissionDenied, "write on")
		// Read live: the same capability is allowed once the person's roles
		// hold write, whatever they are called.
		sp.grant(t, A, "author", sp.person(t, f.Administrator))
		for from, owner := range map[string]string{"the organization": f.Organization, "a person of it": sp.personID(t, f.Administrator)} {
			out, err := sp.transfer(t, asEditorInName, f.StoreCredential, f.Existing, owner, U(t))
			t.Run("from "+from, func(t *testing.T) {
				if err != nil {
					t.Fatal(err)
				}
				if str(out, "principal_id") != U(t) || str(out, "authorized_by") != sp.personID(t, f.Administrator) {
					t.Fatalf("transferred to %s by %s, want %s by the person", str(out, "principal_id"), str(out, "authorized_by"), U(t))
				}
			})
		}
		administers := asEditorInName
		sp.grant(t, A, "author", sp.person(t, f.Reader))
		sp.grant(t, A, "installer", sp.person(t, f.Installer))
		reads := sp.must(t)(sp.through(t, f.Reader, A, "store"))
		installs := sp.must(t)(sp.through(t, f.Installer, A, "store"))
		byAgent := sp.must(t)(sp.agent(t, A, "store"))
		atRoot := sp.must(t)(sp.root(t, f.Administrator, A))
		for name, r := range map[string]struct {
			capability          protoreflect.Message
			actor, id, from, to string
			code                codes.Code
			reason              string
		}{
			"from another solution principal":                {administers, f.StoreCredential, f.Existing, V(t), U(t), codes.PermissionDenied, "solution principal"},
			"from another organization":                      {administers, f.StoreCredential, f.Existing, f.OtherOrganization, U(t), codes.PermissionDenied, "not a person or the organization"},
			"from another organization's person":             {administers, f.StoreCredential, f.Existing, sp.personID(t, f.OtherMember), U(t), codes.PermissionDenied, "not a person or the organization"},
			"from an unknown owner":                          {administers, f.StoreCredential, f.Existing, "unknown-owner", U(t), codes.PermissionDenied, "not a person or the organization"},
			"from no owner":                                  {administers, f.StoreCredential, f.Existing, "", U(t), codes.PermissionDenied, "not a person or the organization"},
			"of a resource the person does not administer":   {administers, f.StoreCredential, f.Existing + "-unadministered", f.Organization, U(t), codes.PermissionDenied, "own organization grants"},
			"to a principal the capability is not through":   {administers, f.StoreCredential, f.Existing, f.Organization, V(t), codes.PermissionDenied, "issued through"},
			"by a reader of the resource":                    {reads, f.StoreCredential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "own organization grants"},
			"by the installer role alone":                    {installs, f.StoreCredential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "own organization grants"},
			"by the installation's agent":                    {byAgent, f.StoreCredential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "a person's act"},
			"asked by a module that does not serve the kind": {administers, f.A.Credential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "does not serve"},
			"with a capability addressed elsewhere":          {atRoot, f.StoreCredential, f.Existing, f.Organization, U(t), codes.Unauthenticated, "audience"},
			"of the wildcard id":                             {administers, f.StoreCredential, "*", f.Organization, U(t), codes.InvalidArgument, "not a usable id"},
			"of an oversize id":                              {administers, f.StoreCredential, strings.Repeat("x", 129), f.Organization, U(t), codes.InvalidArgument, "not a usable id"},
		} {
			_, err := sp.transfer(t, r.capability, r.actor, r.id, r.from, r.to)
			t.Run(name, func(t *testing.T) { refused(t, err, r.code, r.reason) })
		}
	})
	t.Run("revoking a person's role stops their access at once, theirs alone; their old capabilities stay dead after a re-grant", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "author", sp.person(t, f.Editor))
		before := sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		unrelated := sp.must(t)(sp.through(t, f.Editor, A, "store"))
		// A new grant, to the holder or to anyone else, leaves both valid.
		sp.grant(t, A, "author", sp.person(t, f.Viewer))
		sp.grant(t, A, "viewer", sp.person(t, f.Member))
		for _, capability := range []protoreflect.Message{before, unrelated} {
			if err := sp.check(capability); err != nil {
				t.Fatalf("a new grant invalidated an existing capability: %v", err)
			}
		}
		sp.revoke(t, A, "author", sp.person(t, f.Viewer))
		sp.revoke(t, A, "viewer", sp.person(t, f.Member))
		// Reissued, so the last-grant revoke below must kill a live capability.
		before = sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		if !slices.Contains(sp.roleGrants(t, f.Admin, f.Organization, A), "viewer person "+sp.personID(t, f.Viewer)) {
			t.Fatalf("ListRoleGrants does not show the grant: %v", sp.roleGrants(t, f.Admin, f.Organization, A))
		}
		sp.revoke(t, A, "viewer", sp.person(t, f.Viewer))
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		_, err := sp.hop(t, before)
		refused(t, err, codes.PermissionDenied, "revoked")
		_, err = sp.root(t, f.Viewer, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		if err := sp.check(unrelated); err != nil {
			t.Fatalf("revoking one person's role invalidated another's capability: %v", err)
		}
		if slices.Contains(sp.roleGrants(t, f.Admin, f.Organization, A), "viewer person "+sp.personID(t, f.Viewer)) {
			t.Fatal("ListRoleGrants still shows a revoked grant")
		}
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		exactOwnedScope(t, msg(sp.must(t)(sp.through(t, f.Viewer, A, "store")), "context"), f.Kind, []string{"read"}, U(t))
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
	})
	t.Run("a team's role is its members' access; revoking it or leaving the team stops them at once; a direct grant survives the team's revoke", func(t *testing.T) {
		team := map[string]any{"team_id": f.Team}
		sp.grant(t, A, "viewer", team)
		if !slices.Contains(sp.roleGrants(t, f.Admin, f.Organization, A), "viewer team "+f.Team) {
			t.Fatalf("ListRoleGrants does not show the team grant: %v", sp.roleGrants(t, f.Admin, f.Organization, A))
		}
		before := sp.must(t)(sp.through(t, f.TeamMember, A, "store"))
		exactOwnedScope(t, msg(before, "context"), f.Kind, []string{"read"}, U(t))
		sp.revoke(t, A, "viewer", team)
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		_, err := sp.root(t, f.TeamMember, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		// A direct grant and a team grant: revoking the team leaves the direct one.
		sp.grant(t, A, "viewer", sp.person(t, f.TeamMember))
		sp.grant(t, A, "viewer", team)
		sp.revoke(t, A, "viewer", team)
		sp.must(t)(sp.through(t, f.TeamMember, A, "store"))
		sp.revoke(t, A, "viewer", sp.person(t, f.TeamMember))
		sp.grant(t, A, "viewer", team)
		sp.must(t)(sp.through(t, f.TeamMember, A, "store"))
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		leaving := sp.must(t)(sp.through(t, f.TeamLeaver, A, "store"))
		if err := f.RemoveFromTeam(ctx, sp.personID(t, f.TeamLeaver), f.Team); err != nil {
			t.Fatal(err)
		}
		refused(t, sp.check(leaving), codes.PermissionDenied, "revoked")
		_, err = sp.root(t, f.TeamLeaver, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
	})
	t.Run("a person leaving the organization loses the solution's data at once", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.OrgLeaver))
		before := sp.must(t)(sp.through(t, f.OrgLeaver, A, "store"))
		if err := f.RemoveFromOrganization(ctx, sp.personID(t, f.OrgLeaver)); err != nil {
			t.Fatal(err)
		}
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
	})
	t.Run("uninstalling disables the principal at once and its data stays owned; old capabilities stay dead after reinstall and re-grant", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "author", sp.person(t, f.Administrator))
		before := sp.must(t)(sp.through(t, f.Viewer, A, "store"))
		parent := sp.must(t)(sp.root(t, f.Viewer, A))
		administers := sp.must(t)(sp.through(t, f.Administrator, A, "store"))
		byAgent := sp.must(t)(sp.agent(t, A, "store"))
		u, inst := U(t), str(sp.ensure(t, f.Organization, A), "id")
		sp.uninstall(t, f.Organization, A, func() {
			refused(t, sp.check(before), codes.PermissionDenied, "revoked")
			refused(t, sp.check(byAgent), codes.PermissionDenied, "revoked")
			_, err := sp.child(t, parent, A, "store")
			refused(t, err, codes.PermissionDenied, "revoked")
			_, err = sp.transfer(t, administers, f.StoreCredential, f.Existing, f.Organization, u)
			refused(t, err, codes.PermissionDenied, "revoked")
			_, err = sp.agent(t, A, "store")
			refused(t, err, codes.FailedPrecondition, "not installed")
			_, err = sp.root(t, f.Viewer, A)
			refused(t, err, codes.FailedPrecondition, "not installed")
			_, err = c.call(sp.as(t, f.Admin), "host.installation.v1.InstallationService", "GrantRole", map[string]any{
				"organization_id": f.Organization, "installation_id": inst, "role": "viewer", "person_id": sp.personID(t, f.Viewer)})
			refused(t, err, codes.FailedPrecondition, "not installed")
		})
		if U(t) != u {
			t.Fatalf("reinstalled as %s, want %s", U(t), u)
		}
		_, err := sp.root(t, f.Viewer, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		exactOwnedScope(t, msg(sp.must(t)(sp.through(t, f.Viewer, A, "store")), "context"), f.Kind, []string{"read"}, u)
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		refused(t, sp.check(byAgent), codes.PermissionDenied, "revoked")
		_, err = sp.child(t, parent, A, "store")
		refused(t, err, codes.PermissionDenied, "revoked")
	})
}

// The store's method policy: a route requiring read on the kind, and one
// requiring write.
const (
	storeReadMethod  = "/principal.Store/Read"
	storeWriteMethod = "/principal.Store/Write"
)

// deliverAll delivers the store, the legacy store, and the three solutions:
// A and B declaring owner-aware checking, C not.
func (sp *principalSuite) deliverAll(t *testing.T) {
	t.Helper()
	f := sp.f
	sp.deliverStore(t, true)
	if _, err := sp.c.deliver(sp.ctx, sp.delivery(), f.LegacyStore, "module", f.Generation, []string{f.LegacyKind},
		map[string]any{"scope_ceilings": []any{scopeAsk(f.LegacyKind, []string{"read"}, nil)}}, 0); err != nil {
		t.Fatalf("deliver %s: %v", f.LegacyStore, err)
	}
	every := []string{"admin", "create", "read", "write"}
	for _, s := range []SolutionUnderTest{f.A, f.B, f.C} {
		own := s.Solution + ".note"
		doc := map[string]any{
			"scope_ceilings": []any{scopeAsk(own, []string{"read", "write"}, nil)},
			// Role names carry no rank: "editor" declares read only, "author" writes.
			"roles": []any{
				map[string]any{"name": "installer", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, every, nil)}},
				map[string]any{"name": "author", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, []string{"create", "read", "write"}, nil)}},
				map[string]any{"name": "editor", "scopes": []any{scopeAsk(own, []string{"read"}, nil), scopeAsk(f.Kind, []string{"read"}, nil)}},
				map[string]any{"name": "viewer", "scopes": []any{scopeAsk(own, []string{"read"}, nil), scopeAsk(f.Kind, []string{"read"}, nil), scopeAsk(f.LegacyKind, []string{"read"}, nil)}},
			},
		}
		if s != f.C {
			doc["owner_aware"] = true
		}
		if _, err := sp.c.deliver(sp.ctx, sp.delivery(), s.Solution, "solution", f.Generation, []string{own}, doc, 0,
			solutionhost.AuthorityBinding{ID: "store", Audience: f.Store, Operations: map[string][]string{"invoke": {f.Kind + ":admin", f.Kind + ":create", f.Kind + ":read", f.Kind + ":write"}}},
			solutionhost.AuthorityBinding{ID: "legacy", Audience: f.LegacyStore, Operations: map[string][]string{"invoke": {f.LegacyKind + ":read"}}}); err != nil {
			t.Fatalf("deliver %s: %v", s.Solution, err)
		}
	}
}

// deliverStore delivers the store at its next generation, declaring
// owner-aware checking or not.
func (sp *principalSuite) deliverStore(t *testing.T, ownerAware bool) {
	t.Helper()
	f := sp.f
	doc := map[string]any{
		"scope_ceilings": []any{scopeAsk(f.Kind, []string{"admin", "create", "read", "write"}, nil)},
		"methods": []any{
			map[string]any{"method": storeReadMethod, "requires": []any{scopeAsk(f.Kind, []string{"read"}, nil)}},
			map[string]any{"method": storeWriteMethod, "requires": []any{scopeAsk(f.Kind, []string{"write"}, nil)}},
		},
	}
	if ownerAware {
		doc["owner_aware"] = true
	}
	if _, err := sp.c.deliver(sp.ctx, sp.delivery(), f.Store, "module", sp.storeGeneration, []string{f.Kind}, doc, 0,
		solutionhost.AuthorityBinding{ID: "self", Audience: f.Store, Operations: map[string][]string{"invoke": {f.Kind + ":read", f.Kind + ":write"}}},
		solutionhost.AuthorityBinding{ID: "legacy", Audience: f.LegacyStore, Operations: map[string][]string{"invoke": {f.LegacyKind + ":read"}}}); err != nil {
		t.Fatalf("deliver %s: %v", f.Store, err)
	}
	sp.storeGeneration++
}

func (sp *principalSuite) delivery() Fixture {
	return Fixture{SignManifest: sp.f.SignManifest, SignAuthority: sp.f.SignAuthority, DeliveryCredential: sp.f.DeliveryCredential, HostCoordinate: sp.f.HostCoordinate, HostDomain: sp.f.HostDomain,
		InstallModule: sp.f.InstallModule}
}

func countOf(list []string, want string) int {
	n := 0
	for _, v := range list {
		if v == want {
			n++
		}
	}
	return n
}

// principalSuite holds the target's sessions and installations, so each case
// makes its own grants and can run alone.
type principalSuite struct {
	c         *client
	f         SolutionPrincipalCase
	ctx       context.Context
	sessions  map[string]protoreflect.Message
	installed map[string]protoreflect.Message // organization/solution → installation
	// storeGeneration is the store's next delivery generation.
	storeGeneration uint64
}

func (sp *principalSuite) session(t *testing.T, token string) protoreflect.Message {
	t.Helper()
	if s, ok := sp.sessions[token]; ok {
		return s
	}
	s := sp.c.must(t, sp.ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": token})
	sp.sessions[token] = s
	return s
}

func (sp *principalSuite) personID(t *testing.T, token string) string {
	return str(sp.session(t, token), "person_id")
}
func (sp *principalSuite) as(t *testing.T, token string) context.Context {
	return as(sp.ctx, sp.session(t, token))
}
func (sp *principalSuite) person(t *testing.T, token string) map[string]any {
	return map[string]any{"person_id": sp.personID(t, token)}
}

// admin is the administrator of org who installs there.
func (sp *principalSuite) admin(org string) string {
	if org == sp.f.OtherOrganization {
		return sp.f.OtherAdmin
	}
	return sp.f.Admin
}

// ensure installs s at org once, with the agent's role author.
func (sp *principalSuite) ensure(t *testing.T, org string, s SolutionUnderTest) protoreflect.Message {
	t.Helper()
	if inst, ok := sp.installed[org+"/"+s.Solution]; ok {
		return inst
	}
	admin := sp.admin(org)
	out := sp.c.must(t, sp.as(t, admin), "host.installation.v1.InstallationService", "Install", map[string]any{
		"organization_id": org, "target": s.Solution, "role": "author", "owner_person_id": sp.personID(t, admin), "approval": sp.c.reviewInstallation(t, sp.as(t, admin), org, s.Solution)})
	if enumName(out, "status") != "STATUS_ACTIVE" {
		t.Fatalf("%s at %s is %s; the host's install step must converge for the suite's solutions", s.Solution, org, enumName(out, "status"))
	}
	sp.installed[org+"/"+s.Solution] = out
	return out
}

func (sp *principalSuite) principal(t *testing.T, org string, s SolutionUnderTest) string {
	return str(sp.ensure(t, org, s), "principal_id")
}

// uninstall runs the host's uninstall, then each check while it is disabled,
// then reinstalls through the interface.
func (sp *principalSuite) uninstall(t *testing.T, org string, s SolutionUnderTest, whileDisabled ...func()) {
	t.Helper()
	if err := sp.f.Uninstall(sp.ctx, str(sp.ensure(t, org, s), "id")); err != nil {
		t.Fatal(err)
	}
	// The checks name the uninstalled installation; only then is it
	// forgotten and installed again.
	for _, check := range whileDisabled {
		check()
	}
	delete(sp.installed, org+"/"+s.Solution)
	sp.ensure(t, org, s)
}

func (sp *principalSuite) roleAs(t *testing.T, caller, method, org string, s SolutionUnderTest, role string, subject map[string]any) {
	t.Helper()
	request := map[string]any{"organization_id": org, "installation_id": str(sp.ensure(t, org, s), "id"), "role": role}
	for k, v := range subject {
		request[k] = v
	}
	sp.c.must(t, sp.as(t, caller), "host.installation.v1.InstallationService", method, request)
}
func (sp *principalSuite) grant(t *testing.T, s SolutionUnderTest, role string, subject map[string]any) {
	t.Helper()
	sp.roleAs(t, sp.f.Admin, "GrantRole", sp.f.Organization, s, role, subject)
}
func (sp *principalSuite) revoke(t *testing.T, s SolutionUnderTest, role string, subject map[string]any) {
	t.Helper()
	sp.roleAs(t, sp.f.Admin, "RevokeRole", sp.f.Organization, s, role, subject)
}

// roleGrants reads ListRoleGrants, as caller, as "<role> person <id>" or
// "<role> team <id>".
func (sp *principalSuite) roleGrants(t *testing.T, caller, org string, s SolutionUnderTest) []string {
	t.Helper()
	out := sp.c.must(t, sp.as(t, caller), "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{
		"organization_id": org, "installation_id": str(sp.ensure(t, org, s), "id")})
	var grants []string
	for _, g := range listMsgs(out, "grants") {
		if id := str(g, "person_id"); id != "" {
			grants = append(grants, str(g, "role")+" person "+id)
		} else {
			grants = append(grants, str(g, "role")+" team "+str(g, "team_id"))
		}
	}
	return grants
}

func (sp *principalSuite) issue(fields map[string]any) (protoreflect.Message, error) {
	return sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "Issue", fields)
}

// root is a person's capability at s in their own organisation.
func (sp *principalSuite) root(t *testing.T, token string, s SolutionUnderTest) (protoreflect.Message, error) {
	return sp.c.call(sp.as(t, token), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": s.Solution})
}

// child is s's hop on parent through binding, asking scopes.
func (sp *principalSuite) child(t *testing.T, parent protoreflect.Message, s SolutionUnderTest, binding string, scopes ...any) (protoreflect.Message, error) {
	audience := sp.f.Store
	if binding == "legacy" {
		audience = sp.f.LegacyStore
	}
	return sp.issue(map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": s.Credential},
		"operation_binding_id": binding, "audience": audience, "scopes": scopes})
}

// through is a person at s, then s's hop through binding.
func (sp *principalSuite) through(t *testing.T, token string, s SolutionUnderTest, binding string, scopes ...any) (protoreflect.Message, error) {
	t.Helper()
	r, err := sp.root(t, token, s)
	if err != nil {
		return nil, err
	}
	return sp.child(t, r, s, binding, scopes...)
}

// hop is the store's own hop on parent, through its self binding.
func (sp *principalSuite) hop(t *testing.T, parent protoreflect.Message, scopes ...any) (protoreflect.Message, error) {
	return sp.hopTo(t, parent, "self", sp.f.Store, scopes...)
}

// hopTo is the store's own hop on parent through binding to audience.
func (sp *principalSuite) hopTo(t *testing.T, parent protoreflect.Message, binding, audience string, scopes ...any) (protoreflect.Message, error) {
	return sp.issue(map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": sp.f.StoreCredential},
		"operation_binding_id": binding, "audience": audience, "scopes": scopes})
}

// agent is the installation of s acting for itself through binding ("" names none).
func (sp *principalSuite) agent(t *testing.T, s SolutionUnderTest, binding string, scopes ...any) (protoreflect.Message, error) {
	audience := sp.f.Store
	if binding == "legacy" {
		audience = sp.f.LegacyStore
	}
	fields := map[string]any{"installation": map[string]any{"installation_id": str(sp.ensure(t, sp.f.Organization, s), "id")},
		"actor": map[string]any{"credential": s.Credential}, "audience": audience, "scopes": scopes}
	if binding != "" {
		fields["operation_binding_id"] = binding
	}
	return sp.issue(fields)
}

func (sp *principalSuite) owned(kind string, actions []string, owner string, ids ...string) map[string]any {
	ask := scopeAsk(kind, actions, ids)
	ask["resource_owner_id"] = owner
	return ask
}

func (sp *principalSuite) check(capability protoreflect.Message) error {
	_, err := sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(capability, "token"), "audience": sp.f.Store})
	return err
}

func (sp *principalSuite) transfer(t *testing.T, capability protoreflect.Message, actor, id, from, to string) (protoreflect.Message, error) {
	return sp.c.call(sp.ctx, "host.authority.v1.AuthorityService", "AuthorizeTransfer", map[string]any{"token": str(capability, "token"),
		"actor": map[string]any{"credential": actor}, "resource_kind": sp.f.Kind, "resource_id": id, "from_owner_id": from, "to_principal_id": to})
}

// listed requires ListResources to answer exactly want: id ("*" for every
// resource) → its owner.
func (sp *principalSuite) listed(t *testing.T, capability protoreflect.Message, kind, action string, want map[string]string) {
	t.Helper()
	out := sp.c.must(t, sp.ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{"token": str(capability, "token"), "audience": sp.f.Store, "resource_kind": kind, "action": action})
	got := map[string]string{}
	for _, g := range listMsgs(out, "grants") {
		key := str(g, "id")
		if field(g, "all").IsValid() && field(g, "all").Bool() {
			key = "*"
		}
		if key == "" || str(g, "prefix") != "" || str(g, "pattern") != "" {
			t.Fatalf("an owner-selected capability listed %v", g)
		}
		got[key] = str(g, "resource_owner_id")
	}
	if len(got) != len(want) {
		t.Fatalf("listed %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("listed %v, want %v", got, want)
		}
	}
}

// must(t)(call()) stops the case at an unexpected refusal.
func (sp *principalSuite) must(t *testing.T) func(protoreflect.Message, error) protoreflect.Message {
	return func(out protoreflect.Message, err error) protoreflect.Message {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
}

// contractProblems names each target element the descriptors lack, each
// element they still carry that the target deletes, and an owner selector on
// ResourceGrant that would sit inside its match oneof (owner and id must both
// be expressible).
func (c *client) contractProblems() []string {
	var lacks, keeps []string
	for _, want := range solutionPrincipalContract {
		if !c.hasElement(want.message, want.element) {
			name := want.message
			if c.hasElement(want.message, "") {
				name += "." + want.element
			}
			if !slices.Contains(lacks, name) {
				lacks = append(lacks, name)
			}
		}
	}
	for _, gone := range solutionPrincipalRemoved {
		if c.hasElement(gone.message, gone.element) {
			keeps = append(keeps, strings.TrimSuffix(gone.message+"."+gone.element, "."))
		}
	}
	var problems []string
	if len(lacks) > 0 {
		problems = append(problems, "lacks "+strings.Join(lacks, ", "))
	}
	if len(keeps) > 0 {
		problems = append(problems, "still carries "+strings.Join(keeps, ", ")+" (deleted by the target)")
	}
	if d, err := c.files.FindDescriptorByName("host.authority.v1.ResourceGrant"); err == nil {
		if fd := d.(protoreflect.MessageDescriptor).Fields().ByName("resource_owner_id"); fd != nil && fd.ContainingOneof() != nil {
			problems = append(problems, "puts ResourceGrant.resource_owner_id inside a oneof; it qualifies a match")
		}
	}
	if d, err := c.files.FindDescriptorByName("host.authority.v1.WorkScopeV1"); err == nil {
		if fd := d.(protoreflect.MessageDescriptor).Fields().ByName("resource_owner_id"); fd != nil && fd.Number() != 4 {
			problems = append(problems, "numbers WorkScopeV1.resource_owner_id other than 4 (core's field)")
		}
	}
	return problems
}

// hasElement reports whether message (or service) exists and, when element is
// named, has that field (or method).
func (c *client) hasElement(name, element string) bool {
	d, err := c.files.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return false
	}
	if element == "" {
		return true
	}
	switch d := d.(type) {
	case protoreflect.MessageDescriptor:
		return d.Fields().ByName(protoreflect.Name(element)) != nil
	case protoreflect.ServiceDescriptor:
		return d.Methods().ByName(protoreflect.Name(element)) != nil
	}
	return false
}

// installationPrincipal is the principal an installation acts as for itself.
func installationPrincipal(installation protoreflect.Message) string {
	return str(installation, "principal_id")
}

// exactOwnedScope requires the effective scope to be exactly kind and actions
// on resources owned by owner: no id list, no other kind.
func exactOwnedScope(t *testing.T, wc protoreflect.Message, kind string, actions []string, owner string) {
	t.Helper()
	exactOwnedScopeIDs(t, wc, kind, actions, owner, nil)
}

// exactOwnedScopeIDs is exactOwnedScope narrowed to ids within the owner.
func exactOwnedScopeIDs(t *testing.T, wc protoreflect.Message, kind string, actions []string, owner string, ids []string) {
	t.Helper()
	exactEffectiveScope(t, wc, kind, actions, ids)
	scopes := listMsgs(wc, "authority_scopes")
	if actors := listMsgs(wc, "actor_chain"); len(actors) > 0 {
		scopes = listMsgs(actors[len(actors)-1], "granted_scopes")
	}
	for _, scope := range scopes {
		if field(scope, "actions").List().Len() > 0 && str(scope, "resource_owner_id") != owner {
			t.Fatalf("scope on %s is owned by %q, want %q", kind, str(scope, "resource_owner_id"), owner)
		}
	}
}

func listStrings(m protoreflect.Message, name string) []string {
	l := field(m, name).List()
	out := make([]string, l.Len())
	for i := range out {
		out[i] = l.Get(i).String()
	}
	return out
}

// noRole is the reason a person holding no role on a solution is refused.
func (c *client) noRole() string { return "holds no role" }

// installationOwner is the principal owning data reached through installation
// id at f.Organization: its principal_id under the target contract, "" before
// it (the earlier model's scopes name no owner).
func (c *client) installationOwner(t *testing.T, ctx context.Context, f Fixture, match func(protoreflect.Message) bool) string {
	t.Helper()
	admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
	list := c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})
	for _, inst := range listMsgs(list, "installations") {
		if match(inst) {
			return str(inst, "principal_id")
		}
	}
	t.Fatal("required conformance fixture missing: the installation the case reaches")
	return ""
}

func (c *client) solutionOwner(t *testing.T, ctx context.Context, f Fixture, solution string) string {
	return c.installationOwner(t, ctx, f, func(inst protoreflect.Message) bool { return str(inst, "target") == solution })
}

func (c *client) installationOwnerByID(t *testing.T, ctx context.Context, f Fixture, id string) string {
	return c.installationOwner(t, ctx, f, func(inst protoreflect.Message) bool { return str(inst, "id") == id })
}

// ownedBy selects ask's resources by owner, when the contract has owners.
func ownedBy(ask map[string]any, owner string) map[string]any {
	if owner != "" {
		ask["resource_owner_id"] = owner
	}
	return ask
}

// exactScopeOwnedBy is exactEffectiveScope, owner-selected when owner is set.
func exactScopeOwnedBy(t *testing.T, wc protoreflect.Message, kind string, actions, ids []string, owner string) {
	t.Helper()
	if owner == "" {
		exactEffectiveScope(t, wc, kind, actions, ids)
		return
	}
	exactOwnedScopeIDs(t, wc, kind, actions, owner, ids)
}

// heldOwner is the owner of what the session holds on kind at audience under
// the solution-principal contract (a solution's principal), "" before it, at a
// module audience, or when the person holds nothing there.
func (c *client) heldOwner(ctx context.Context, sess protoreflect.Message, audience, kind string) string {
	out, err := c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": audience})
	if err != nil {
		return ""
	}
	for _, scope := range listMsgs(msg(out, "context"), "authority_scopes") {
		if str(scope, "resource_kind") == kind {
			return str(scope, "resource_owner_id")
		}
	}
	return ""
}
