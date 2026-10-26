package conformance

import (
	"context"
	"regexp"
	"slices"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SolutionPrincipalCase is the TARGET contract for solution identity; no host
// passes it yet. An installed solution is a principal of its organisation, with
// a stable UUID like a person's. Its declared roles are permission levels on
// the data that principal owns, and granting a person a role is the access.
// A capability carries owner-selected scopes: {kind, actions, resource owner},
// never lists of ids, so a module admits a resource whose owner is the scope's.
//
// The suite delivers A, B (two solutions) and Store (the module serving Kind)
// at Generation, installs A and B through InstallationService, and grants every
// role itself. The host supplies people and one existing resource:
//   - Admin administers Organization; it installs and grants. Its own
//     organisation grants hold nothing on Kind.
//   - Viewer, Editor and Member hold no role on A or B until the suite grants
//     one; their organisation grants on Kind are irrelevant to the case.
//   - Administrator holds admin on Existing, and Reader holds read on Existing,
//     each from their own organisation grants at Store and on nothing else of
//     Kind. Existing is a resource of Kind no solution principal owns.
//
// Uninstall is the host's uninstall path for an installation id (the interface
// has no uninstall operation). The host's install step must converge for the
// suite's solutions, so Install answers an active installation.
type SolutionPrincipalCase struct {
	Organization                  string
	A, B                          SolutionUnderTest
	Store, StoreCredential, Kind  string
	Generation                    uint64
	Admin, Viewer, Editor, Member string
	Administrator, Reader         string
	Existing                      string
	Uninstall                     func(ctx context.Context, installationID string) error
	SignManifest, SignAuthority   func(document []byte) ([]byte, error)
	DeliveryCredential            func(module string) string
	HostCoordinate, HostDomain    string
}

// SolutionUnderTest is one solution the suite delivers and installs.
type SolutionUnderTest struct {
	Solution, Credential string
}

// solutionPrincipalContract is what the target adds to the published contract.
// Its absence is the first, named failure of every case.
var solutionPrincipalContract = []struct{ message, element string }{
	{"host.installation.v1.Installation", "principal_id"},
	{"host.installation.v1.Installation", "roles"},
	{"host.installation.v1.InstallationService", "GrantRole"},
	{"host.installation.v1.GrantRoleRequest", "organization_id"},
	{"host.installation.v1.GrantRoleRequest", "installation_id"},
	{"host.installation.v1.GrantRoleRequest", "role"},
	{"host.installation.v1.GrantRoleRequest", "person_id"},
	{"host.installation.v1.GrantRoleRequest", "team_id"},
	{"host.authority.v1.WorkScopeV1", "resource_owner_id"},
	{"host.authority.v1.ResourceGrant", "owner"},
	{"host.authority.v1.AuthorityService", "AuthorizeTransfer"},
	{"host.authority.v1.AuthorizeTransferRequest", "token"},
	{"host.authority.v1.AuthorizeTransferRequest", "actor"},
	{"host.authority.v1.AuthorizeTransferRequest", "resource_kind"},
	{"host.authority.v1.AuthorizeTransferRequest", "resource_id"},
	{"host.authority.v1.AuthorizeTransferRequest", "to_principal_id"},
	{"host.authority.v1.AuthorizeTransferResponse", "principal_id"},
}

var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RunSolutionPrincipalTarget drives the target over one connection. It is not
// part of Run until a host implements it.
func RunSolutionPrincipalTarget(t *testing.T, conn grpc.ClientConnInterface, descriptors []byte, f SolutionPrincipalCase) {
	t.Helper()
	c, err := newClient(conn, descriptors)
	if err != nil {
		t.Fatalf("conformance: %v", err)
	}
	if missing := c.missingContract(); len(missing) > 0 {
		t.Fatalf("target: the published contract lacks %v", missing)
	}
	if f.Uninstall == nil || f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.Existing == "" ||
		f.Admin == "" || f.Viewer == "" || f.Editor == "" || f.Member == "" || f.Administrator == "" || f.Reader == "" {
		t.Fatal("required conformance fixture missing: solution principal case")
	}
	ctx := context.Background()
	const binding, self = "store", "self"
	all := []string{f.Kind + ":admin", f.Kind + ":create", f.Kind + ":read", f.Kind + ":write"}
	delivery := Fixture{SignManifest: f.SignManifest, SignAuthority: f.SignAuthority, DeliveryCredential: f.DeliveryCredential, HostCoordinate: f.HostCoordinate, HostDomain: f.HostDomain}
	if _, err := c.deliver(ctx, delivery, f.Store, "module", f.Generation, []string{f.Kind},
		map[string]any{"scope_ceilings": []any{scopeAsk(f.Kind, []string{"admin", "create", "read", "write"}, nil)}}, 0,
		solutionhost.AuthorityBinding{ID: self, Audience: f.Store, Operations: map[string][]string{"invoke": {f.Kind + ":read", f.Kind + ":write"}}}); err != nil {
		t.Fatalf("deliver %s: %v", f.Store, err)
	}
	// Each role is a level on the principal's data: no role names an owner,
	// since the owner is always the installation's own principal.
	for _, s := range []SolutionUnderTest{f.A, f.B} {
		own := s.Solution + ".note"
		doc := map[string]any{
			"scope_ceilings": []any{scopeAsk(own, []string{"read", "write"}, nil)},
			"roles": []any{
				map[string]any{"name": "installer", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, []string{"admin", "create", "read", "write"}, nil)}},
				map[string]any{"name": "editor", "scopes": []any{scopeAsk(own, []string{"read", "write"}, nil), scopeAsk(f.Kind, []string{"create", "read", "write"}, nil)}},
				map[string]any{"name": "viewer", "scopes": []any{scopeAsk(own, []string{"read"}, nil), scopeAsk(f.Kind, []string{"read"}, nil)}},
			},
		}
		if _, err := c.deliver(ctx, delivery, s.Solution, "solution", f.Generation, []string{own}, doc, 0,
			solutionhost.AuthorityBinding{ID: binding, Audience: f.Store, Operations: map[string][]string{"invoke": all}}); err != nil {
			t.Fatalf("deliver %s: %v", s.Solution, err)
		}
	}

	sessions := map[string]protoreflect.Message{}
	session := func(t *testing.T, token string) protoreflect.Message {
		t.Helper()
		if s, ok := sessions[token]; ok {
			return s
		}
		s := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": token})
		sessions[token] = s
		return s
	}
	personID := func(t *testing.T, token string) string { return str(session(t, token), "person_id") }
	asPerson := func(t *testing.T, token string) context.Context { return as(ctx, session(t, token)) }
	installed := map[string]protoreflect.Message{}
	install := func(t *testing.T, s SolutionUnderTest) protoreflect.Message {
		t.Helper()
		out := c.must(t, asPerson(t, f.Admin), "host.installation.v1.InstallationService", "Install", map[string]any{
			"organization_id": f.Organization, "target": s.Solution, "role": "editor", "owner_person_id": personID(t, f.Admin)})
		if enumName(out, "status") != "STATUS_ACTIVE" {
			t.Fatalf("%s is %s; the host's install step must converge for the suite's solutions", s.Solution, enumName(out, "status"))
		}
		installed[s.Solution] = out
		return out
	}
	principal := func(s SolutionUnderTest) string { return str(installed[s.Solution], "principal_id") }
	grant := func(t *testing.T, s SolutionUnderTest, role, token string) {
		t.Helper()
		c.must(t, asPerson(t, f.Admin), "host.installation.v1.InstallationService", "GrantRole", map[string]any{
			"organization_id": f.Organization, "installation_id": str(installed[s.Solution], "id"), "role": role, "person_id": personID(t, token)})
	}
	issue := func(fields map[string]any) (protoreflect.Message, error) {
		return c.call(ctx, "host.authority.v1.AuthorityService", "Issue", fields)
	}
	root := func(t *testing.T, token string, s SolutionUnderTest) (protoreflect.Message, error) {
		return c.call(asPerson(t, token), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": s.Solution})
	}
	// through is a person at s, then s's hop to Store asking scopes.
	through := func(t *testing.T, token string, s SolutionUnderTest, scopes ...any) (protoreflect.Message, error) {
		t.Helper()
		r, err := root(t, token, s)
		if err != nil {
			return nil, err
		}
		return issue(map[string]any{"parent_token": str(r, "token"), "actor": map[string]any{"credential": s.Credential},
			"operation_binding_id": binding, "audience": f.Store, "scopes": scopes})
	}
	hop := func(parent protoreflect.Message, scopes ...any) (protoreflect.Message, error) {
		return issue(map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": f.StoreCredential},
			"operation_binding_id": self, "audience": f.Store, "scopes": scopes})
	}
	agent := func(s SolutionUnderTest, scopes ...any) (protoreflect.Message, error) {
		return issue(map[string]any{"installation": map[string]any{"installation_id": str(installed[s.Solution], "id")},
			"actor": map[string]any{"credential": s.Credential}, "audience": f.Store, "scopes": scopes})
	}
	owned := func(actions []string, owner string) map[string]any {
		ask := scopeAsk(f.Kind, actions, nil)
		ask["resource_owner_id"] = owner
		return ask
	}
	transfer := func(token, to string) (protoreflect.Message, error) {
		return c.call(ctx, "host.authority.v1.AuthorityService", "AuthorizeTransfer", map[string]any{"token": token,
			"actor": map[string]any{"credential": f.StoreCredential}, "resource_kind": f.Kind, "resource_id": f.Existing, "to_principal_id": to})
	}
	// must(t)(call()) stops the case at an unexpected refusal.
	must := func(t *testing.T) func(protoreflect.Message, error) protoreflect.Message {
		return func(out protoreflect.Message, err error) protoreflect.Message {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
	}

	t.Run("install creates the solution principal and its roles; a reinstall keeps its UUID", func(t *testing.T) {
		a, b := install(t, f.A), install(t, f.B)
		for _, inst := range []protoreflect.Message{a, b} {
			id := str(inst, "principal_id")
			if !canonicalUUID.MatchString(id) || id == str(inst, "id") || id == str(inst, "agent_principal_id") {
				t.Fatalf("principal_id %q is not a principal UUID of its own", id)
			}
			if got := slices.Sorted(slices.Values(listStrings(inst, "roles"))); !slices.Equal(got, []string{"editor", "installer", "viewer"}) {
				t.Fatalf("the installation's roles are %v, want the solution's declared roles", got)
			}
		}
		if principal(f.A) == principal(f.B) {
			t.Fatal("two installations share a principal")
		}
		before := principal(f.A)
		if err := f.Uninstall(ctx, str(a, "id")); err != nil {
			t.Fatal(err)
		}
		if install(t, f.A); principal(f.A) != before {
			t.Fatalf("a reinstall made principal %s, want %s: its data would be orphaned", principal(f.A), before)
		}
	})
	t.Run("without a role on the solution a person is refused, naming the reason", func(t *testing.T) {
		_, err := root(t, f.Viewer, f.A)
		refused(t, err, codes.PermissionDenied, "holds no role")
	})
	t.Run("a viewer reads what the principal owns, and nothing another installation or a person owns", func(t *testing.T) {
		grant(t, f.A, "viewer", f.Viewer)
		out := must(t)(through(t, f.Viewer, f.A))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, principal(f.A))
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": f.Store})
		listed := c.must(t, ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{"token": str(out, "token"), "audience": f.Store, "resource_kind": f.Kind, "action": "read"})
		grants := listMsgs(listed, "grants")
		if len(grants) != 1 || str(grants[0], "owner") != principal(f.A) {
			t.Fatalf("listed %v, want exactly the resources principal %s owns", grants, principal(f.A))
		}
		for name, ask := range map[string]any{
			"another installation's data": owned([]string{"read"}, principal(f.B)),
			"the whole kind":              scopeAsk(f.Kind, []string{"read"}, nil),
			"a resource it does not own":  scopeAsk(f.Kind, []string{"read"}, []string{f.Existing}),
		} {
			_, err := through(t, f.Viewer, f.A, ask)
			t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
		}
	})
	t.Run("a resource created through the solution is owned by its principal, the person its author", func(t *testing.T) {
		grant(t, f.A, "editor", f.Editor)
		out := must(t)(through(t, f.Editor, f.A, owned([]string{"create"}, principal(f.A))))
		wc := msg(out, "context")
		exactOwnedScope(t, wc, f.Kind, []string{"create"}, principal(f.A))
		if str(wc, "owner_principal_id") != personID(t, f.Editor) || str(wc, "owner_principal_kind") != "human" {
			t.Fatalf("the author is %s (%s), want the person", str(wc, "owner_principal_id"), str(wc, "owner_principal_kind"))
		}
		// The installation acting for itself creates for the same principal.
		byAgent := must(t)(agent(f.A, owned([]string{"create"}, principal(f.A))))
		exactOwnedScope(t, msg(byAgent, "context"), f.Kind, []string{"create"}, principal(f.A))
		if str(msg(byAgent, "context"), "owner_principal_kind") != "agent" {
			t.Fatal("an installation acting for itself is its agent")
		}
	})
	t.Run("an editor writes and a viewer cannot, each by name", func(t *testing.T) {
		out := must(t)(through(t, f.Editor, f.A, owned([]string{"write"}, principal(f.A))))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"write"}, principal(f.A))
		_, err := through(t, f.Viewer, f.A, owned([]string{"write"}, principal(f.A)))
		refused(t, err, codes.PermissionDenied, "widens")
	})
	t.Run("another installation's members never reach the principal's data", func(t *testing.T) {
		grant(t, f.B, "viewer", f.Member)
		_, err := root(t, f.Member, f.A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		out := must(t)(through(t, f.Member, f.B))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, principal(f.B))
		_, err = through(t, f.Member, f.B, owned([]string{"read"}, principal(f.A)))
		refused(t, err, codes.PermissionDenied, "widens")
	})
	t.Run("a child never widens the owner or the actions it narrowed to", func(t *testing.T) {
		narrowed := must(t)(through(t, f.Viewer, f.A, owned([]string{"read"}, principal(f.A))))
		next := must(t)(hop(narrowed))
		exactOwnedScope(t, msg(next, "context"), f.Kind, []string{"read"}, principal(f.A))
		for name, ask := range map[string]any{
			"another owner":  owned([]string{"read"}, principal(f.B)),
			"the whole kind": scopeAsk(f.Kind, []string{"read"}, nil),
		} {
			_, err := hop(narrowed, ask)
			t.Run(name, func(t *testing.T) { refused(t, err, codes.PermissionDenied, "widens") })
		}
		readOnly := must(t)(through(t, f.Editor, f.A, owned([]string{"read"}, principal(f.A))))
		_, err := hop(readOnly, owned([]string{"write"}, principal(f.A)))
		refused(t, err, codes.PermissionDenied, "widens")
	})
	t.Run("an existing resource joins the principal only by a transfer its person administers through their own grants", func(t *testing.T) {
		grant(t, f.A, "viewer", f.Administrator)
		grant(t, f.A, "viewer", f.Reader)
		administers := must(t)(through(t, f.Administrator, f.A))
		out := must(t)(transfer(str(administers, "token"), principal(f.A)))
		if str(out, "principal_id") != principal(f.A) {
			t.Fatalf("transferred to %s, want %s", str(out, "principal_id"), principal(f.A))
		}
		_, err := transfer(str(administers, "token"), principal(f.B))
		refused(t, err, codes.PermissionDenied, "issued through")
		reads := must(t)(through(t, f.Reader, f.A))
		_, err = transfer(str(reads, "token"), principal(f.A))
		refused(t, err, codes.PermissionDenied, "own organisation grants")
		// The installer's role administers the principal's data, not Existing.
		installer := must(t)(through(t, f.Admin, f.A))
		_, err = transfer(str(installer, "token"), principal(f.A))
		refused(t, err, codes.PermissionDenied, "own organisation grants")
		byAgent := must(t)(agent(f.A))
		_, err = transfer(str(byAgent, "token"), principal(f.A))
		refused(t, err, codes.PermissionDenied, "a person's act")
	})
	t.Run("uninstalling disables the principal at once and its data stays owned; a re-grant after reinstall restores access", func(t *testing.T) {
		before := must(t)(through(t, f.Viewer, f.A))
		u := principal(f.A)
		if err := f.Uninstall(ctx, str(installed[f.A.Solution], "id")); err != nil {
			t.Fatal(err)
		}
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(before, "token"), "audience": f.Store})
		refused(t, err, codes.PermissionDenied, "")
		_, err = agent(f.A)
		refused(t, err, codes.PermissionDenied, "")
		if install(t, f.A); principal(f.A) != u {
			t.Fatalf("reinstalled as %s, want %s", principal(f.A), u)
		}
		_, err = root(t, f.Viewer, f.A)
		refused(t, err, codes.PermissionDenied, "holds no role")
		grant(t, f.A, "viewer", f.Viewer)
		out := must(t)(through(t, f.Viewer, f.A))
		exactOwnedScope(t, msg(out, "context"), f.Kind, []string{"read"}, u)
	})
}

// missingContract names each target element the published descriptors lack.
func (c *client) missingContract() []string {
	var missing []string
	for _, want := range solutionPrincipalContract {
		d, err := c.files.FindDescriptorByName(protoreflect.FullName(want.message))
		if err != nil {
			if !slices.Contains(missing, want.message) {
				missing = append(missing, want.message)
			}
			continue
		}
		switch d := d.(type) {
		case protoreflect.MessageDescriptor:
			if d.Fields().ByName(protoreflect.Name(want.element)) == nil {
				missing = append(missing, want.message+"."+want.element)
			}
		case protoreflect.ServiceDescriptor:
			if d.Methods().ByName(protoreflect.Name(want.element)) == nil {
				missing = append(missing, want.message+"/"+want.element)
			}
		}
	}
	return missing
}

// exactOwnedScope requires the effective scope to be exactly kind and actions
// on resources owned by owner: no id list, no other kind.
func exactOwnedScope(t *testing.T, wc protoreflect.Message, kind string, actions []string, owner string) {
	t.Helper()
	exactEffectiveScope(t, wc, kind, actions, nil)
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
