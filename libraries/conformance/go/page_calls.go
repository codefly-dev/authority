package conformance

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// One rule for every page, the one its backend is held to, on every host: a
// person's Issue naming page_target, made by the host's module edge (its own
// workload credential as the actor), is issued through the page's target's
// binding to the audience when the target declares one — the person's role on
// the target cut to the binding, its one actor the target as the person
// present on the page (kind "page") — and on the person's own access when the
// target declares none. Only the module edge names a page: the same Issue
// with no actor, or with any other workload's credential, is refused.
const (
	pageCallModule = "conformance-page-calls"
	pageCallNote   = pageCallModule + ".note"
	pageActorKind  = "page"
)

func (c *client) pageCalls(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("a page's call goes through its target's binding, the person present, named by the module edge alone", func(t *testing.T) {
		if f.EdgeCredential == "" || f.WorkloadCredential == "" || f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" || f.Audience == "" || f.ReadKind == "" || f.Elsewhere == "" {
			t.Fatal("required conformance fixture missing: the module edge's credential (EdgeCredential), a module's (WorkloadCredential), signed delivery, an administrator, a member holding no role (UnentitledToken), a composed module without roles serving ReadKind (Audience) and another (Elsewhere)")
		}
		page := &solutionhost.Frontend{Title: "Conformance page calls", ExposedModule: "./Page", HostContract: 1, Payload: f.PagePayload}
		document := map[string]any{"scope_ceilings": []any{scopeAsk(pageCallNote, []string{"read", "write"}, nil)}, "installation_role": "none", "roles": []any{
			map[string]any{"name": "installer", "scopes": []any{scopeAsk(pageCallNote, []string{"read", "write"}, nil), scopeAsk(f.ReadKind, []string{"read"}, nil)}},
			map[string]any{"name": "viewer", "scopes": []any{scopeAsk(pageCallNote, []string{"read"}, nil), scopeAsk(f.ReadKind, []string{"read"}, nil)}},
		}}
		rows := solutionhost.AuthorityBinding{ID: "rows", Audience: f.Audience, Operations: map[string][]string{"invoke": {f.ReadKind + ":read"}}}
		if _, err := c.deliverPage(ctx, f, page, pageCallModule, "module", 1, []string{pageCallNote}, document, 0, rows); err != nil {
			t.Fatalf("deliver %s with a page, roles and a binding to %s: %v", pageCallModule, f.Audience, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		var id string
		for _, inst := range listMsgs(c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization}), "installations") {
			if str(inst, "target") == pageCallModule && enumName(inst, "status") == "STATUS_ACTIVE" {
				id = str(inst, "id")
			}
		}
		if id == "" {
			t.Fatalf("%s is not installed by composition", pageCallModule)
		}
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "GrantRole", map[string]any{
			"organization_id": f.Organization, "installation_id": id, "role": "viewer", "person_id": str(holder, "person_id")})
		issue := func(actor, audience string, scopes ...any) (protoreflect.Message, error) {
			fields := map[string]any{"person": map[string]any{}, "audience": audience, "page_target": pageCallModule}
			if actor != "" {
				fields["actor"] = map[string]any{"credential": actor}
			}
			if len(scopes) > 0 {
				fields["scopes"] = scopes
			}
			return c.call(as(ctx, holder), "host.authority.v1.AuthorityService", "Issue", fields)
		}
		out, err := issue(f.EdgeCredential, f.Audience)
		if err != nil {
			t.Fatalf("the viewer's page call at %s: %v", f.Audience, err)
		}
		chain := listMsgs(msg(out, "context"), "actor_chain")
		if len(chain) != 1 || str(chain[0], "principal_id") != pageCallModule || str(chain[0], "principal_kind") != pageActorKind {
			t.Fatalf("the page's call is the target's page hop, the person present: %v", chain)
		}
		granted := listMsgs(chain[0], "granted_scopes")
		if len(granted) != 1 || str(granted[0], "resource_kind") != f.ReadKind || len(listStrings(granted[0], "actions")) != 1 || listStrings(granted[0], "actions")[0] != "read" {
			t.Fatalf("the viewer's role cut to the binding: %v", granted)
		}
		_, err = issue(f.EdgeCredential, f.Audience, scopeAsk(f.ReadKind, []string{"write"}, nil))
		refused(t, err, codes.PermissionDenied, "widens")
		_, err = issue(f.EdgeCredential, f.Elsewhere)
		if codeOf := status.Code(err); codeOf != codes.PermissionDenied {
			t.Fatalf("a module the target declares no binding to is on the person's own access, which holds nothing there: %v", err)
		}
		for _, actor := range []string{"", f.WorkloadCredential} {
			_, err := issue(actor, f.Audience)
			refused(t, err, codes.PermissionDenied, "module edge")
		}
	})
}
