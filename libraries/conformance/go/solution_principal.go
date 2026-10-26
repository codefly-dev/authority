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
// An installed solution is a principal of its organisation (U), with a stable
// UUID like a person's: one per (organisation, solution), reused by a
// reinstall, disabled by an uninstall. The installation acting for itself IS
// U, holding the role its install request names; nobody else inherits that
// role. The solution's declared roles are permission levels on U's data:
// granting a person or a team a role (GrantRole) is the access, revoking it
// (RevokeRole) ends it at once, and ListRoleGrants answers who holds which.
// An organisation administrator, or a holder of the solution's installer role,
// grants and revokes.
//
// A capability issued through the solution is CONFINED to U's data: its
// scopes are owner-selected, {kind, actions, resource_owner_id: U}, from the
// solution's roles alone; a person's own organisation grants never flow in. A
// scope naming an owner and ids admits a resource only when both match. The
// authority issues owner-selected scopes only to an audience whose delivery
// declares owner-aware checking (AuthorityManifestV1.owner_aware).
//
// An existing resource joins U only by AuthorizeTransfer: the store (the
// kind's serving module, which attests the resource exists and who owns it
// now) asks; the authority allows it from a person- or organisation-owned
// resource, never from another solution principal, when the person holds admin
// on it from their own organisation grants AND at least editor on U. The store
// then records U as owner; the original creator stays the author, and the
// previous owner keeps nothing through ownership.
//
// The suite delivers A, B, Store and LegacyStore, installs A and B, and makes
// every grant itself. The host supplies, at Organization unless stated:
//   - Admin: an organisation administrator (whatever its own grants on Kind).
//   - Viewer, Editor, Member, Installer, TeamMember, TeamLeaver, OrgLeaver:
//     members with no role on A or B but what the suite grants; TeamMember and
//     TeamLeaver belong to Team.
//   - Administrator holds admin, and Reader holds read, on Existing from their
//     own organisation grants at Store, and nothing else of Kind.
//   - OtherAdmin and OtherMember: an administrator and a member of
//     OtherOrganization.
//   - Existing: a resource of Kind owned by Organization.
//   - Uninstall, RemoveFromTeam, RemoveFromOrganization: the host's own paths
//     (the interface has none). Install must converge for the suite's solutions.
type SolutionPrincipalCase struct {
	Organization, OtherOrganization                string
	A, B                                           SolutionUnderTest
	Store, StoreCredential, Kind                   string
	LegacyStore, LegacyStoreCredential, LegacyKind string
	Generation                                     uint64
	Admin, Viewer, Editor, Member, Installer       string
	Team, TeamMember, TeamLeaver, OrgLeaver        string
	Administrator, Reader, OtherAdmin, OtherMember string
	Existing                                       string
	Uninstall                                      func(ctx context.Context, installationID string) error
	RemoveFromTeam                                 func(ctx context.Context, personID, team string) error
	RemoveFromOrganization                         func(ctx context.Context, personID string) error
	SignManifest, SignAuthority                    func(document []byte) ([]byte, error)
	DeliveryCredential                             func(module string) string
	HostCoordinate, HostDomain                     string
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
// part of Run until a host implements it; when it joins, it supersedes Run's
// GrantToTeam and team_ids cases (installation_lifecycle.go's exposure steps,
// the callee-staleness probe's GrantToTeam) and reads the installation's
// acting principal as principal_id (installationPrincipal).
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
		f.DeliveryCredential == nil || f.Existing == "" || f.OtherOrganization == "" || f.LegacyStore == "" || f.Team == "" ||
		slices.Contains([]string{f.Admin, f.Viewer, f.Editor, f.Member, f.Installer, f.TeamMember, f.TeamLeaver, f.OrgLeaver, f.Administrator, f.Reader, f.OtherAdmin, f.OtherMember}, "") {
		t.Fatal("required conformance fixture missing: solution principal case")
	}
	ctx := context.Background()
	const binding, legacy, self = "store", "legacy", "self"
	delivery := Fixture{SignManifest: f.SignManifest, SignAuthority: f.SignAuthority, DeliveryCredential: f.DeliveryCredential, HostCoordinate: f.HostCoordinate, HostDomain: f.HostDomain}
	every := []string{"admin", "create", "read", "write"}
	if _, err := c.deliver(ctx, delivery, f.Store, "module", f.Generation, []string{f.Kind},
		map[string]any{"scope_ceilings": []any{scopeAsk(f.Kind, every, nil)}, "owner_aware": true}, 0,
		solutionhost.AuthorityBinding{ID: self, Audience: f.Store, Operations: map[string][]string{"invoke": {f.Kind + ":read", f.Kind + ":write"}}}); err != nil {
		t.Fatalf("deliver %s: %v", f.Store, err)
	}
	// The legacy store does not declare owner-aware checking.
	if _, err := c.deliver(ctx, delivery, f.LegacyStore, "module", f.Generation, []string{f.LegacyKind},
		map[string]any{"scope_ceilings": []any{scopeAsk(f.LegacyKind, []string{"read"}, nil)}}, 0); err != nil {
		t.Fatalf("deliver %s: %v", f.LegacyStore, err)
	}
	// Each role is a level on the principal's data; no role names an owner.
	for _, s := range []SolutionUnderTest{f.A, f.B} {
		own := s.Solution + ".note"
		doc := map[string]any{
			"scope_ceilings": []any{scopeAsk(own, []string{"read", "write"}, nil)},
			"roles": []any{
				map[string]any{"name": "installer", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, every, nil)}},
				map[string]any{"name": "editor", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, []string{"create", "read", "write"}, nil)}},
				map[string]any{"name": "viewer", "scopes": []any{scopeAsk(own, []string{"read"}, nil), scopeAsk(f.Kind, []string{"read"}, nil), scopeAsk(f.LegacyKind, []string{"read"}, nil)}},
			},
		}
		if _, err := c.deliver(ctx, delivery, s.Solution, "solution", f.Generation, []string{own}, doc, 0,
			solutionhost.AuthorityBinding{ID: binding, Audience: f.Store, Operations: map[string][]string{"invoke": {f.Kind + ":admin", f.Kind + ":create", f.Kind + ":read", f.Kind + ":write"}}},
			solutionhost.AuthorityBinding{ID: legacy, Audience: f.LegacyStore, Operations: map[string][]string{"invoke": {f.LegacyKind + ":read"}}}); err != nil {
			t.Fatalf("deliver %s: %v", s.Solution, err)
		}
	}

	sp := &principalSuite{c: c, f: f, ctx: ctx, sessions: map[string]protoreflect.Message{}, installed: map[string]protoreflect.Message{}}
	A, B := f.A, f.B
	U := func(t *testing.T) string { return sp.principal(t, f.Organization, A) }
	V := func(t *testing.T) string { return sp.principal(t, f.Organization, B) }

	t.Run("install creates the solution principal and its roles; a reinstall keeps its UUID; another organisation's is another principal", func(t *testing.T) {
		a, b := sp.ensure(t, f.Organization, A), sp.ensure(t, f.Organization, B)
		for _, inst := range []protoreflect.Message{a, b} {
			if id := str(inst, "principal_id"); !principalUUID.MatchString(id) || id == str(inst, "id") {
				t.Fatalf("principal_id %q is not a principal UUID of its own", id)
			}
			if got := slices.Sorted(slices.Values(listStrings(inst, "roles"))); !slices.Equal(got, []string{"editor", "installer", "viewer"}) {
				t.Fatalf("the installation's roles are %v, want the solution's declared roles", got)
			}
		}
		if U(t) == V(t) {
			t.Fatal("two installations share a principal")
		}
		if other := sp.principal(t, f.OtherOrganization, A); other == U(t) {
			t.Fatal("one solution installed in two organisations shares a principal")
		}
		before := U(t)
		sp.uninstall(t, f.Organization, A)
		if after := U(t); after != before {
			t.Fatalf("a reinstall made principal %s, want %s: its data would be orphaned", after, before)
		}
	})
	t.Run("the install request's role is the agent's, and no person's: the owner and the organisation administrator hold no role", func(t *testing.T) {
		byAgent := sp.must(t)(sp.agent(t, A, binding))
		wc := msg(byAgent, "context")
		exactOwnedScope(t, wc, f.Kind, []string{"create", "read", "write"}, U(t))
		if str(wc, "owner_principal_kind") != "agent" || str(wc, "owner_principal_id") != U(t) {
			t.Fatalf("the installation acting for itself is %s (%s), want the solution principal %s", str(wc, "owner_principal_id"), str(wc, "owner_principal_kind"), U(t))
		}
		_, err := sp.agent(t, A, binding, sp.owned(f.Kind, []string{"admin"}, U(t)))
		refused(t, err, codes.PermissionDenied, "beyond")
		_, err = sp.agent(t, A, "")
		refused(t, err, codes.PermissionDenied, "binding")
		_, err = sp.root(t, f.Admin, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		if got := sp.roleGrants(t, A); len(got) != 0 {
			t.Fatalf("an installation nobody was granted lists %v", got)
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
		out := sp.must(t)(sp.through(t, f.Viewer, A, binding))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, U(t))
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Store})
		sp.listed(t, out, f.Kind, "read", map[string]string{"*": U(t)})
		narrowed := sp.must(t)(sp.through(t, f.Viewer, A, binding, sp.owned(f.Kind, []string{"read"}, U(t), "u-doc")))
		exactOwnedScopeIDs(t, msg(narrowed, "context"), f.Kind, []string{"read"}, U(t), []string{"u-doc"})
		sp.listed(t, narrowed, f.Kind, "read", map[string]string{"u-doc": U(t)})
		for name, ask := range map[string]any{
			"another installation's principal": sp.owned(f.Kind, []string{"read"}, V(t)),
			"another principal's ids":          sp.owned(f.Kind, []string{"read"}, V(t), "u-doc"),
			"another organisation's principal": sp.owned(f.Kind, []string{"read"}, sp.principal(t, f.OtherOrganization, A)),
			"the whole kind":                   scopeAsk(f.Kind, []string{"read"}, nil),
			"a resource by id alone":           scopeAsk(f.Kind, []string{"read"}, []string{f.Existing}),
			"a person as owner":                sp.owned(f.Kind, []string{"read"}, sp.personID(t, f.Viewer)),
			"the installation id as owner":     sp.owned(f.Kind, []string{"read"}, str(sp.ensure(t, f.Organization, A), "id")),
			"the organisation as owner":        sp.owned(f.Kind, []string{"read"}, f.Organization),
		} {
			_, err := sp.through(t, f.Viewer, A, binding, ask)
			t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
		}
	})
	t.Run("a capability through the solution is confined to the principal's data; the person's own grants never flow in", func(t *testing.T) {
		for _, token := range []string{f.Reader, f.Administrator} {
			sp.grant(t, A, "viewer", sp.person(t, token))
			out := sp.must(t)(sp.through(t, token, A, binding))
			exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, U(t))
		}
		_, err := sp.through(t, f.Reader, A, binding, scopeAsk(f.Kind, []string{"read"}, []string{f.Existing}))
		refused(t, err, codes.PermissionDenied, "confined")
		_, err = sp.through(t, f.Administrator, A, binding, scopeAsk(f.Kind, []string{"admin"}, []string{f.Existing}))
		refused(t, err, codes.PermissionDenied, "confined")
	})
	t.Run("owner-selected scopes are issued only to an audience that checks owners", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		_, err := sp.through(t, f.Viewer, A, legacy)
		refused(t, err, codes.PermissionDenied, "owner-aware")
		_, err = sp.agent(t, A, legacy)
		refused(t, err, codes.PermissionDenied, "owner-aware")
	})
	t.Run("a resource created through the solution is owned by its principal, the person its author", func(t *testing.T) {
		sp.grant(t, A, "editor", sp.person(t, f.Editor))
		out := sp.must(t)(sp.through(t, f.Editor, A, binding, sp.owned(f.Kind, []string{"create"}, U(t))))
		wc := msg(out, "context")
		exactOwnedScope(t, wc, f.Kind, []string{"create"}, U(t))
		if str(wc, "owner_principal_id") != sp.personID(t, f.Editor) || str(wc, "owner_principal_kind") != "human" {
			t.Fatalf("the author is %s (%s), want the person", str(wc, "owner_principal_id"), str(wc, "owner_principal_kind"))
		}
		byAgent := sp.must(t)(sp.agent(t, A, binding, sp.owned(f.Kind, []string{"create"}, U(t))))
		exactOwnedScope(t, msg(byAgent, "context"), f.Kind, []string{"create"}, U(t))
	})
	t.Run("an editor writes and a viewer cannot, each by name", func(t *testing.T) {
		sp.grant(t, A, "editor", sp.person(t, f.Editor))
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		out := sp.must(t)(sp.through(t, f.Editor, A, binding, sp.owned(f.Kind, []string{"write"}, U(t))))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"write"}, U(t))
		_, err := sp.through(t, f.Viewer, A, binding, sp.owned(f.Kind, []string{"write"}, U(t)))
		refused(t, err, codes.PermissionDenied, "widens")
	})
	t.Run("an organisation administrator or the solution's installer grants; anyone else, and every malformed grant, is refused by name", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "installer", sp.person(t, f.Installer))
		// The installer role grants and revokes on its own installation.
		sp.roleAs(t, f.Installer, "GrantRole", f.Organization, A, "viewer", sp.person(t, f.Member))
		sp.roleAs(t, f.Installer, "RevokeRole", f.Organization, A, "viewer", sp.person(t, f.Member))
		inst := str(sp.ensure(t, f.Organization, A), "id")
		for name, r := range map[string]struct {
			caller string
			fields map[string]any
			code   codes.Code
			reason string
		}{
			"a viewer granting itself installer": {f.Viewer, map[string]any{"organization_id": f.Organization, "installation_id": inst, "role": "installer", "person_id": sp.personID(t, f.Viewer)}, codes.PermissionDenied, "may not grant"},
			"another organisation's id":          {f.Admin, map[string]any{"organization_id": f.OtherOrganization, "installation_id": inst, "role": "viewer", "person_id": sp.personID(t, f.Member)}, codes.PermissionDenied, "organization"},
			"an undeclared role":                 {f.Admin, map[string]any{"organization_id": f.Organization, "installation_id": inst, "role": "owner", "person_id": sp.personID(t, f.Member)}, codes.NotFound, "declares no role"},
			"both a person and a team":           {f.Admin, map[string]any{"organization_id": f.Organization, "installation_id": inst, "role": "viewer", "person_id": sp.personID(t, f.Member), "team_id": f.Team}, codes.InvalidArgument, "exactly one"},
			"neither a person nor a team":        {f.Admin, map[string]any{"organization_id": f.Organization, "installation_id": inst, "role": "viewer"}, codes.InvalidArgument, "exactly one"},
			"a person of another organisation":   {f.Admin, map[string]any{"organization_id": f.Organization, "installation_id": inst, "role": "viewer", "person_id": sp.personID(t, f.OtherMember)}, codes.PermissionDenied, "not a member"},
		} {
			t.Run(name, func(t *testing.T) {
				_, err := c.call(sp.as(t, r.caller), "host.installation.v1.InstallationService", "GrantRole", r.fields)
				refused(t, err, r.code, r.reason)
			})
		}
		_, err := c.call(sp.as(t, f.Viewer), "host.installation.v1.InstallationService", "RevokeRole", map[string]any{"organization_id": f.Organization, "installation_id": inst, "role": "installer", "person_id": sp.personID(t, f.Installer)})
		refused(t, err, codes.PermissionDenied, "may not grant")
		_, err = c.call(sp.as(t, f.Viewer), "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": inst})
		refused(t, err, codes.PermissionDenied, "may not")
	})
	t.Run("another installation's and another organisation's members never reach the principal's data", func(t *testing.T) {
		sp.grant(t, B, "viewer", sp.person(t, f.Member))
		_, err := sp.root(t, f.Member, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		out := sp.must(t)(sp.through(t, f.Member, B, binding))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, V(t))
		_, err = sp.through(t, f.Member, B, binding, sp.owned(f.Kind, []string{"read"}, U(t)))
		refused(t, err, codes.PermissionDenied, "widens")
		other := sp.principal(t, f.OtherOrganization, A)
		sp.roleIn(t, f.OtherAdmin, f.OtherOrganization, A, "viewer", sp.person(t, f.OtherMember))
		elsewhere := sp.must(t)(sp.through(t, f.OtherMember, A, binding))
		exactOwnedScope(t, msg(elsewhere, "context"), f.Kind, []string{"read"}, other)
		_, err = sp.through(t, f.OtherMember, A, binding, sp.owned(f.Kind, []string{"read"}, U(t)))
		refused(t, err, codes.PermissionDenied, "widens")
	})
	t.Run("a child never widens the owner, the actions or the ids it narrowed to", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "editor", sp.person(t, f.Editor))
		narrowed := sp.must(t)(sp.through(t, f.Viewer, A, binding, sp.owned(f.Kind, []string{"read"}, U(t))))
		exactOwnedScope(t, msg(sp.must(t)(sp.hop(t, narrowed)), "context"), f.Kind, []string{"read"}, U(t))
		readOnly := sp.must(t)(sp.through(t, f.Editor, A, binding, sp.owned(f.Kind, []string{"read"}, U(t))))
		oneDoc := sp.must(t)(sp.through(t, f.Viewer, A, binding, sp.owned(f.Kind, []string{"read"}, U(t), "u-doc")))
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
	t.Run("an existing resource joins the principal only by a transfer from a person or the organisation, administered through the person's own grants, by an editor of the principal", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Administrator))
		asViewer := sp.must(t)(sp.through(t, f.Administrator, A, binding))
		_, err := sp.transfer(t, asViewer, f.StoreCredential, f.Existing, f.Organization, U(t))
		refused(t, err, codes.PermissionDenied, "editor")
		sp.grant(t, A, "editor", sp.person(t, f.Administrator))
		administers := sp.must(t)(sp.through(t, f.Administrator, A, binding))
		for from, owner := range map[string]string{"the organisation": f.Organization, "a person": sp.personID(t, f.Administrator)} {
			out, err := sp.transfer(t, administers, f.StoreCredential, f.Existing, owner, U(t))
			t.Run("from "+from, func(t *testing.T) {
				if err != nil {
					t.Fatal(err)
				}
				if str(out, "principal_id") != U(t) || str(out, "authorized_by") != sp.personID(t, f.Administrator) {
					t.Fatalf("transferred to %s by %s, want %s by the person", str(out, "principal_id"), str(out, "authorized_by"), U(t))
				}
			})
		}
		sp.grant(t, A, "editor", sp.person(t, f.Reader))
		sp.grant(t, A, "installer", sp.person(t, f.Installer))
		reads := sp.must(t)(sp.through(t, f.Reader, A, binding))
		installs := sp.must(t)(sp.through(t, f.Installer, A, binding))
		byAgent := sp.must(t)(sp.agent(t, A, binding))
		atRoot := sp.must(t)(sp.root(t, f.Administrator, A))
		for name, r := range map[string]struct {
			capability          protoreflect.Message
			actor, id, from, to string
			code                codes.Code
			reason              string
		}{
			"from another solution principal":                {administers, f.StoreCredential, f.Existing, V(t), U(t), codes.PermissionDenied, "solution principal"},
			"to a principal the capability is not through":   {administers, f.StoreCredential, f.Existing, f.Organization, V(t), codes.PermissionDenied, "issued through"},
			"by a reader of the resource":                    {reads, f.StoreCredential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "own organisation grants"},
			"by the installer role alone":                    {installs, f.StoreCredential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "own organisation grants"},
			"by the installation's agent":                    {byAgent, f.StoreCredential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "a person's act"},
			"asked by a module that does not serve the kind": {administers, f.A.Credential, f.Existing, f.Organization, U(t), codes.PermissionDenied, "does not serve"},
			"with a capability addressed elsewhere":          {atRoot, f.StoreCredential, f.Existing, f.Organization, U(t), codes.Unauthenticated, "audience"},
			"of the wildcard id":                             {administers, f.StoreCredential, "*", f.Organization, U(t), codes.PermissionDenied, "not a usable id"},
			"of an oversize id":                              {administers, f.StoreCredential, strings.Repeat("x", 129), f.Organization, U(t), codes.PermissionDenied, "not a usable id"},
		} {
			_, err := sp.transfer(t, r.capability, r.actor, r.id, r.from, r.to)
			t.Run(name, func(t *testing.T) { refused(t, err, r.code, r.reason) })
		}
	})
	t.Run("revoking a person's role stops their access at once, theirs alone; their old capabilities stay dead after a re-grant", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "editor", sp.person(t, f.Editor))
		before := sp.must(t)(sp.through(t, f.Viewer, A, binding))
		unrelated := sp.must(t)(sp.through(t, f.Editor, A, binding))
		if !slices.Contains(sp.roleGrants(t, A), "viewer person "+sp.personID(t, f.Viewer)) {
			t.Fatalf("ListRoleGrants does not show the grant: %v", sp.roleGrants(t, A))
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
		if slices.Contains(sp.roleGrants(t, A), "viewer person "+sp.personID(t, f.Viewer)) {
			t.Fatal("ListRoleGrants still shows a revoked grant")
		}
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		exactOwnedScope(t, msg(sp.must(t)(sp.through(t, f.Viewer, A, binding)), "context"), f.Kind, []string{"read"}, U(t))
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
	})
	t.Run("a team's role is its members' access; revoking it or leaving the team stops them at once; old capabilities stay dead after a re-grant", func(t *testing.T) {
		team := map[string]any{"team_id": f.Team}
		sp.grant(t, A, "viewer", team)
		if !slices.Contains(sp.roleGrants(t, A), "viewer team "+f.Team) {
			t.Fatalf("ListRoleGrants does not show the team grant: %v", sp.roleGrants(t, A))
		}
		before := sp.must(t)(sp.through(t, f.TeamMember, A, binding))
		exactOwnedScope(t, msg(before, "context"), f.Kind, []string{"read"}, U(t))
		sp.revoke(t, A, "viewer", team)
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		_, err := sp.root(t, f.TeamMember, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		sp.grant(t, A, "viewer", team)
		sp.must(t)(sp.through(t, f.TeamMember, A, binding))
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		leaving := sp.must(t)(sp.through(t, f.TeamLeaver, A, binding))
		if err := f.RemoveFromTeam(ctx, sp.personID(t, f.TeamLeaver), f.Team); err != nil {
			t.Fatal(err)
		}
		refused(t, sp.check(leaving), codes.PermissionDenied, "revoked")
		_, err = sp.root(t, f.TeamLeaver, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
	})
	t.Run("a person leaving the organisation loses the solution's data at once", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.OrgLeaver))
		before := sp.must(t)(sp.through(t, f.OrgLeaver, A, binding))
		if err := f.RemoveFromOrganization(ctx, sp.personID(t, f.OrgLeaver)); err != nil {
			t.Fatal(err)
		}
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
	})
	t.Run("uninstalling disables the principal at once and its data stays owned; old capabilities stay dead after reinstall and re-grant", func(t *testing.T) {
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		sp.grant(t, A, "editor", sp.person(t, f.Administrator))
		before := sp.must(t)(sp.through(t, f.Viewer, A, binding))
		parent := sp.must(t)(sp.root(t, f.Viewer, A))
		administers := sp.must(t)(sp.through(t, f.Administrator, A, binding))
		u := U(t)
		sp.uninstall(t, f.Organization, A, func() {
			refused(t, sp.check(before), codes.PermissionDenied, "revoked")
			_, err := sp.child(t, parent, A, binding)
			refused(t, err, codes.PermissionDenied, "revoked")
			_, err = sp.transfer(t, administers, f.StoreCredential, f.Existing, f.Organization, u)
			refused(t, err, codes.PermissionDenied, "revoked")
			_, err = sp.agent(t, A, binding)
			refused(t, err, codes.FailedPrecondition, "not installed")
			_, err = sp.root(t, f.Viewer, A)
			refused(t, err, codes.FailedPrecondition, "not installed")
		})
		if U(t) != u {
			t.Fatalf("reinstalled as %s, want %s", U(t), u)
		}
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
		_, err := sp.root(t, f.Viewer, A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		sp.grant(t, A, "viewer", sp.person(t, f.Viewer))
		exactOwnedScope(t, msg(sp.must(t)(sp.through(t, f.Viewer, A, binding)), "context"), f.Kind, []string{"read"}, u)
		refused(t, sp.check(before), codes.PermissionDenied, "revoked")
	})
}

// principalSuite holds the target's sessions and installations, so each case
// makes its own grants and can run alone.
type principalSuite struct {
	c         *client
	f         SolutionPrincipalCase
	ctx       context.Context
	sessions  map[string]protoreflect.Message
	installed map[string]protoreflect.Message // organisation/solution → installation
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

// ensure installs s at org once, with the agent's role editor.
func (sp *principalSuite) ensure(t *testing.T, org string, s SolutionUnderTest) protoreflect.Message {
	t.Helper()
	if inst, ok := sp.installed[org+"/"+s.Solution]; ok {
		return inst
	}
	admin := sp.admin(org)
	out := sp.c.must(t, sp.as(t, admin), "host.installation.v1.InstallationService", "Install", map[string]any{
		"organization_id": org, "target": s.Solution, "role": "editor", "owner_person_id": sp.personID(t, admin)})
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
	delete(sp.installed, org+"/"+s.Solution)
	for _, check := range whileDisabled {
		check()
	}
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
func (sp *principalSuite) roleIn(t *testing.T, caller, org string, s SolutionUnderTest, role string, subject map[string]any) {
	t.Helper()
	sp.roleAs(t, caller, "GrantRole", org, s, role, subject)
}

// roleGrants reads ListRoleGrants as "<role> person <id>" or "<role> team <id>".
func (sp *principalSuite) roleGrants(t *testing.T, s SolutionUnderTest) []string {
	t.Helper()
	out := sp.c.must(t, sp.as(t, sp.f.Admin), "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{
		"organization_id": sp.f.Organization, "installation_id": str(sp.ensure(t, sp.f.Organization, s), "id")})
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
	return sp.issue(map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": sp.f.StoreCredential},
		"operation_binding_id": "self", "audience": sp.f.Store, "scopes": scopes})
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

// installationPrincipal is the principal an installation acts as for itself:
// principal_id under the target contract, agent_principal_id before it. Run
// reads it so one host passes both Run and the target.
func installationPrincipal(installation protoreflect.Message) string {
	if id := str(installation, "principal_id"); id != "" {
		return id
	}
	return str(installation, "agent_principal_id")
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
