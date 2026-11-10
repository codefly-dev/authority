package conformance

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// A module that declares a page declares roles as a solution does, and is
// installed by composition as every module is: in every organization on
// delivery, holding no principal and no standing authority, never offered,
// reviewed or installed by an administrator. Its roles decide who is listed
// for it and who may use it: what a person holds at it is the roles granted
// them, or a team of theirs, on its composition installation, never the
// organization's roles. A module without a page declares none, and a module
// page declaring none keeps the organization's. The holder is
// UnentitledToken (no role, no team); ViewerToken is another member, of at
// least one team, whose organization roles read ReadKind: the module serves
// ReadKind too, so they would hold it there were organization roles to
// decide.
const (
	pageModule      = "conformance-page-module"
	pageModuleNote  = pageModule + ".note"
	headlessModule  = "conformance-headless-roles"
	headlessNote    = headlessModule + ".note"
	pageModuleTitle = "Conformance page"
)

func (c *client) modulePageRoles(t *testing.T, ctx context.Context, f Fixture) {
	c.run(t, f, "a module page is installed by composition; its roles decide who is listed for it and who may use it", func(t *testing.T, c *client, f Fixture) {
		if f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.OtherAdminToken == "" || f.UnentitledToken == "" || f.ViewerToken == "" || f.Audience == "" || f.ReadKind == "" {
			t.Fatal("required conformance fixture missing: signed delivery, an administrator here and in another organization, a viewer reading ReadKind, a member holding no role (UnentitledToken) and a composed module without roles (Audience)")
		}
		page := &solutionhost.Frontend{Title: pageModuleTitle, ExposedModule: "./Page", HostContract: 1, Payload: f.PagePayload}
		roles := func(note string, extra ...string) map[string]any {
			declared := []any{
				map[string]any{"name": "installer", "scopes": []any{scopeAsk(note, []string{"read", "write"}, nil)}},
				map[string]any{"name": "viewer", "scopes": []any{scopeAsk(note, []string{"read"}, nil)}},
			}
			for _, name := range extra {
				declared = append(declared, map[string]any{"name": name, "scopes": []any{scopeAsk(note, []string{"read", "write"}, nil)}})
			}
			return map[string]any{"scope_ceilings": []any{scopeAsk(note, []string{"read", "write"}, nil)}, "installation_role": "none", "roles": declared}
		}
		served := []string{pageModuleNote, f.ReadKind}
		if _, err := c.deliverPage(ctx, f, page, pageModule, "module", 1, served, roles(pageModuleNote), 0); err != nil {
			t.Fatalf("deliver %s with a page and roles: %v", pageModule, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		other := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.OtherAdminToken})
		// installed is the module page's installation at the organization
		// sess administers, as its administrator lists it.
		installed := func(t *testing.T, sess protoreflect.Message) protoreflect.Message {
			t.Helper()
			org := str(sess, "organization_id")
			for _, inst := range listMsgs(c.must(t, as(ctx, sess), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": org}), "installations") {
				if str(inst, "target") == pageModule && enumName(inst, "status") == "STATUS_ACTIVE" {
					return inst
				}
			}
			t.Fatalf("%s is not installed active at %s", pageModule, org)
			return nil
		}
		offered := func(t *testing.T, target string) bool {
			t.Helper()
			listed := c.must(t, adminCtx, "host.installation.v1.OfferService", "ListOffers", map[string]any{"organization_id": f.Organization})
			for _, o := range listMsgs(listed, "offers") {
				if str(o, "target") == target {
					return true
				}
			}
			return false
		}
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})

		var id string
		t.Run("a module is installed by composition in every organisation", func(t *testing.T) {
			for _, sess := range []protoreflect.Message{admin, other} {
				inst := installed(t, sess)
				if r := str(inst, "role"); r != "" && r != "none" {
					t.Fatalf("the module page's installation at %s holds %q; a module holds no standing authority", str(sess, "organization_id"), r)
				}
			}
			id = str(installed(t, admin), "id")
		})
		if id == "" {
			t.Fatalf("%s was not installed by composition", pageModule)
		}
		t.Run("a module is never offered, reviewed or installed by an administrator", func(t *testing.T) {
			for _, target := range []string{pageModule, f.Audience} {
				if f.ReviewOfferNotServed == "" {
					if offered(t, target) {
						t.Fatalf("%s, a module, is offered", target)
					}
					_, err := c.call(adminCtx, "host.installation.v1.OfferService", "ReviewOffer", map[string]any{"organization_id": f.Organization, "target": target})
					refused(t, err, codes.NotFound, "installed by composition")
				}
				_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Review", map[string]any{"organization_id": f.Organization, "target": target})
				refused(t, err, codes.NotFound, "installed by composition")
				_, err = c.call(adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{"organization_id": f.Organization, "target": target, "owner_person_id": str(admin, "person_id"),
					"approval": map[string]any{"target_id": target, "generation": uint64(1), "digest": "sha256:made-up", "operation_id": "00000000-0000-4000-8000-000000000000"}})
				refused(t, err, codes.NotFound, "installed by composition")
			}
		})
		grant := func(method, name string, subject map[string]any) error {
			fields := map[string]any{"organization_id": f.Organization, "installation_id": id, "role": name}
			for k, v := range subject {
				fields[k] = v
			}
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", method, fields)
			return err
		}
		person := map[string]any{"person_id": str(holder, "person_id")}
		role := func(method, name string) error { return grant(method, name, person) }
		issue := func(sess protoreflect.Message, scopes ...any) (protoreflect.Message, error) {
			fields := map[string]any{"person": map[string]any{}, "audience": pageModule}
			if len(scopes) > 0 {
				fields["scopes"] = scopes
			}
			return c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", fields)
		}
		list := func(capability protoreflect.Message) (protoreflect.Message, error) {
			return c.call(ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{
				"token": str(capability, "token"), "audience": pageModule, "resource_kind": pageModuleNote, "action": "read"})
		}
		// listed is the roles sess's ListHeld names on the module page's
		// installation; nil when it is not listed.
		listed := func(t *testing.T, sess protoreflect.Message) []string {
			t.Helper()
			out := c.must(t, as(ctx, sess), "host.installation.v1.InstallationService", "ListHeld", map[string]any{"organization_id": f.Organization})
			for _, h := range listMsgs(out, "installations") {
				if str(msg(h, "installation"), "id") == id {
					return listStrings(h, "roles")
				}
			}
			return nil
		}
		readKind := scopeAsk(f.ReadKind, []string{"read"}, nil)

		t.Run("installed, it entitles nobody until a role is granted", func(t *testing.T) {
			for name, sess := range map[string]protoreflect.Message{"the holder": holder, "the viewer": viewer} {
				_, err := issue(sess)
				refused(t, err, codes.PermissionDenied, c.noRole())
				if got := listed(t, sess); got != nil {
					t.Fatalf("%s is listed for %s holding %v before any grant", name, pageModule, got)
				}
			}
		})
		t.Run("a role granted to a team lists the page for a member and entitles them to it", func(t *testing.T) {
			teams := listStrings(viewer, "team_ids")
			if len(teams) == 0 {
				t.Fatal("required conformance fixture missing: ViewerToken signs in a member of at least one team")
			}
			team := map[string]any{"team_id": teams[0]}
			if err := grant("GrantRole", "viewer", team); err != nil {
				t.Fatal(err)
			}
			if got := listed(t, viewer); !slices.Equal(got, []string{"viewer"}) {
				t.Fatalf("a member of team %s lists %s holding %v, want [viewer]", teams[0], pageModule, got)
			}
			out, err := issue(viewer)
			if err != nil {
				t.Fatal(err)
			}
			exactScopeOwnedBy(t, msg(out, "context"), pageModuleNote, []string{"read"}, nil, "")
			if err := grant("RevokeRole", "viewer", team); err != nil {
				t.Fatal(err)
			}
			if got := listed(t, viewer); got != nil {
				t.Fatalf("the team's role revoked, its member still lists %s holding %v", pageModule, got)
			}
		})
		if err := role("GrantRole", "viewer"); err != nil {
			t.Fatal(err)
		}
		var held protoreflect.Message
		t.Run("the role holder is listed for it and entitled to exactly the role", func(t *testing.T) {
			if got := listed(t, holder); !slices.Equal(got, []string{"viewer"}) {
				t.Fatalf("the holder lists %s holding %v, want [viewer]", pageModule, got)
			}
			out, err := issue(holder)
			if err != nil {
				t.Fatal(err)
			}
			exactScopeOwnedBy(t, msg(out, "context"), pageModuleNote, []string{"read"}, nil, "")
			c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": pageModule})
			held = out
		})
		t.Run("the role holder lists the page's resources by the role", func(t *testing.T) {
			if held == nil {
				t.Skip("the holder was issued nothing")
			}
			got, err := list(held)
			if err != nil {
				t.Fatal(err)
			}
			if grants := grantsOf(got); len(grants) != 1 || !grants[0].All {
				t.Fatalf("the holder lists %v, want every %s by the role", grants, pageModuleNote)
			}
		})
		t.Run("another member holds and lists nothing there, whatever the organization grants them", func(t *testing.T) {
			_, err := issue(viewer)
			refused(t, err, codes.PermissionDenied, c.noRole())
			_, err = issue(viewer, readKind)
			refused(t, err, codes.PermissionDenied, c.noRole())
		})
		t.Run("a revoked holder lists nothing", func(t *testing.T) {
			if held == nil {
				t.Skip("the holder was issued nothing")
			}
			if err := role("RevokeRole", "viewer"); err != nil {
				t.Fatal(err)
			}
			_, err := list(held)
			refused(t, err, codes.PermissionDenied, "")
			if err := role("GrantRole", "viewer"); err != nil {
				t.Fatal(err)
			}
			if held, err = issue(holder); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("a role the module does not declare is refused", func(t *testing.T) {
			refused(t, role("GrantRole", "editor"), codes.NotFound, `declares no role "editor"`)
		})
		t.Run("a module that gains or loses roles keeps its installation: a role added keeps its grants", func(t *testing.T) {
			if _, err := c.deliverPage(ctx, f, page, pageModule, "module", 2, served, roles(pageModuleNote, "editor"), 0); err != nil {
				t.Fatalf("redeliver %s adding a role: %v", pageModule, err)
			}
			if got := str(installed(t, admin), "id"); got != id {
				t.Fatalf("a role added moved the module page's installation from %s to %s", id, got)
			}
			if got := listed(t, holder); !slices.Equal(got, []string{"viewer"}) {
				t.Fatalf("a role added left the holder listed holding %v, want [viewer]", got)
			}
			if held != nil {
				c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(held, "token"), "audience": pageModule})
			}
			if err := role("GrantRole", "editor"); err != nil {
				t.Fatalf("the added role is not grantable: %v", err)
			}
			if err := role("RevokeRole", "editor"); err != nil {
				t.Fatal(err)
			}
		})
		t.Run("a module declaring roles and no page is refused", func(t *testing.T) {
			_, err := c.deliver(ctx, f, headlessModule, "module", 1, []string{headlessNote}, roles(headlessNote), 0)
			refused(t, err, codes.PermissionDenied, "no page")
		})
		t.Run("a module that gains or loses roles keeps its installation: every role dropped, the organization's roles decide", func(t *testing.T) {
			// Still no standing authority: a module declares none, roles or not.
			if _, err := c.deliverPage(ctx, f, page, pageModule, "module", 3, served, map[string]any{"scope_ceilings": []any{scopeAsk(pageModuleNote, []string{"read", "write"}, nil)}, "installation_role": "none"}, 0); err != nil {
				t.Fatalf("redeliver %s without roles: %v", pageModule, err)
			}
			if got := str(installed(t, admin), "id"); got != id {
				t.Fatalf("dropping its roles moved the module page's installation from %s to %s", id, got)
			}
			if held != nil {
				_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(held, "token"), "audience": pageModule})
				refused(t, err, codes.PermissionDenied, "")
			}
			if got := listed(t, holder); got != nil {
				t.Fatalf("the dropped roles left the holder listed holding %v", got)
			}
			_, err := issue(holder)
			refused(t, err, codes.PermissionDenied, "holds nothing")
			refused(t, role("GrantRole", "viewer"), codes.NotFound, `declares no role "viewer"`)
			out, err := issue(viewer, readKind)
			if err != nil {
				t.Fatalf("organization roles do not decide again: %v", err)
			}
			exactScopeOwnedBy(t, msg(out, "context"), f.ReadKind, []string{"read"}, nil, "")
			if f.ReviewOfferNotServed == "" && offered(t, pageModule) {
				t.Fatalf("%s is offered once it declares no roles", pageModule)
			}
		})
	})
}
