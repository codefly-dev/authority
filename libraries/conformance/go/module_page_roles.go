package conformance

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// A module that declares a page declares roles as a solution does: what a
// person holds at it is the roles granted them on its organization's
// installation, never the organization's roles. A module without a page
// declares none, and a module page declaring none keeps the organization's.
// The holder is UnentitledToken (no role, no team); ViewerToken is another
// member, whose organization roles read ReadKind: the module serves ReadKind
// too, so they would hold it there were organization roles to decide.
const (
	pageModule      = "conformance-page-module"
	pageModuleNote  = pageModule + ".note"
	headlessModule  = "conformance-headless-roles"
	headlessNote    = headlessModule + ".note"
	pageModuleTitle = "Conformance page"
)

func (c *client) modulePageRoles(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("a module that declares a page declares roles like a solution", func(t *testing.T) {
		if f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" || f.ViewerToken == "" {
			t.Fatal("required conformance fixture missing: signed delivery, an administrator, a viewer and a member holding no role (UnentitledToken)")
		}
		page := &solutionhost.Frontend{Title: pageModuleTitle, ExposedModule: "./Page", HostContract: 1, Payload: f.PagePayload}
		roles := func(note string) map[string]any {
			return map[string]any{"scope_ceilings": []any{scopeAsk(note, []string{"read", "write"}, nil)}, "roles": []any{
				map[string]any{"name": "installer", "scopes": []any{scopeAsk(note, []string{"read", "write"}, nil)}},
				map[string]any{"name": "viewer", "scopes": []any{scopeAsk(note, []string{"read"}, nil)}},
			}}
		}
		if f.ReadKind == "" {
			t.Fatal("required conformance fixture missing: ReadKind, which ViewerToken's organization roles read")
		}
		served := []string{pageModuleNote, f.ReadKind}
		if _, err := c.deliverPage(ctx, f, page, pageModule, "module", 1, served, roles(pageModuleNote), 0); err != nil {
			t.Fatalf("deliver %s with a page and roles: %v", pageModule, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		var id string
		for _, inst := range listMsgs(c.must(t, adminCtx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization}), "installations") {
			if str(inst, "target") == pageModule && enumName(inst, "status") == "STATUS_ACTIVE" {
				id = str(inst, "id")
			}
		}
		if id == "" {
			t.Fatalf("%s is not installed at %s once delivered", pageModule, f.Organization)
		}
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		role := func(method, name string) error {
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", method, map[string]any{
				"organization_id": f.Organization, "installation_id": id, "role": name, "person_id": str(holder, "person_id")})
			return err
		}
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
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		readKind := scopeAsk(f.ReadKind, []string{"read"}, nil)
		if err := role("GrantRole", "viewer"); err != nil {
			t.Fatal(err)
		}
		offered := func(t *testing.T) bool {
			t.Helper()
			listed := c.must(t, adminCtx, "host.installation.v1.OfferService", "ListOffers", map[string]any{"organization_id": f.Organization})
			for _, o := range listMsgs(listed, "offers") {
				if str(o, "target") == pageModule {
					return true
				}
			}
			return false
		}
		t.Run("its setup reviews its roles, with nothing to consent to", func(t *testing.T) {
			if f.ReviewOfferNotServed != "" {
				t.Skipf("this host does not serve OfferService yet: %s", f.ReviewOfferNotServed)
			}
			if !offered(t) {
				t.Fatalf("an administrator's offers at %s do not list %s", f.Organization, pageModule)
			}
			review := func(sess protoreflect.Message) (protoreflect.Message, error) {
				return c.call(as(ctx, sess), "host.installation.v1.OfferService", "ReviewOffer", map[string]any{"organization_id": f.Organization, "target": pageModule})
			}
			for name, sess := range map[string]protoreflect.Message{"the administrator": admin, "the role holder": holder} {
				out, err := review(sess)
				if err != nil {
					t.Fatalf("%s reviews %s: %v", name, pageModule, err)
				}
				var roles []string
				for _, r := range listMsgs(out, "roles") {
					roles = append(roles, str(r, "name"))
				}
				slices.Sort(roles)
				if !slices.Equal(roles, []string{"installer", "viewer"}) || str(msg(out, "installation"), "id") != id {
					t.Fatalf("%s reviews roles %v at installation %q, want [installer viewer] at %q", name, roles, str(msg(out, "installation"), "id"), id)
				}
				if out.Has(out.Descriptor().Fields().ByName("approval")) {
					t.Fatalf("%s is handed a consent tuple for %s, which composition installs", name, pageModule)
				}
			}
			_, err := review(viewer)
			refused(t, err, codes.PermissionDenied, "requires an administrator")
		})
		var held protoreflect.Message
		t.Run("the role holder is entitled to exactly the role", func(t *testing.T) {
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
			listed, err := list(held)
			if err != nil {
				t.Fatal(err)
			}
			if got := grantsOf(listed); len(got) != 1 || !got[0].All {
				t.Fatalf("the viewer lists %v, want every %s by the role", got, pageModuleNote)
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
		})
		t.Run("a role the module does not declare is refused", func(t *testing.T) {
			refused(t, role("GrantRole", "editor"), codes.NotFound, `declares no role "editor"`)
		})
		t.Run("a module declaring roles and no page is refused", func(t *testing.T) {
			_, err := c.deliver(ctx, f, headlessModule, "module", 1, []string{headlessNote}, roles(headlessNote), 0)
			refused(t, err, codes.PermissionDenied, "no page")
		})
		t.Run("a module page declaring no roles keeps the organization's", func(t *testing.T) {
			if _, err := c.deliverPage(ctx, f, page, pageModule, "module", 2, served, map[string]any{"scope_ceilings": []any{scopeAsk(pageModuleNote, []string{"read", "write"}, nil)}}, 0); err != nil {
				t.Fatalf("redeliver %s without roles: %v", pageModule, err)
			}
			if held != nil {
				_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(held, "token"), "audience": pageModule})
				refused(t, err, codes.PermissionDenied, "")
			}
			_, err := issue(holder)
			refused(t, err, codes.PermissionDenied, "holds nothing")
			refused(t, role("GrantRole", "viewer"), codes.NotFound, `declares no role "viewer"`)
			out, err := issue(viewer, readKind)
			if err != nil {
				t.Fatalf("organization roles do not decide again: %v", err)
			}
			exactScopeOwnedBy(t, msg(out, "context"), f.ReadKind, []string{"read"}, nil, "")
			if f.ReviewOfferNotServed == "" && offered(t) {
				t.Fatalf("%s is still offered once it declares no roles", pageModule)
			}
		})
		if err := role("RevokeRole", "viewer"); err != nil {
			t.Fatal(err)
		}
	})
}
