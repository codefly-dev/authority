package conformance

import (
	"context"
	"testing"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ParentLimitsCase is a root with two held kinds and a self binding to both.
// Out and Back cross an unrelated audience, returning to the root's first kind.
type ParentLimitsCase struct {
	Token, Root, Credential, SelfBinding                                  string
	Kind, DroppedKind, Action, DroppedAction, ResourceID, OtherResourceID string
	Out, Back                                                             Hop
}

func (c *client) parentLimits(t *testing.T, ctx context.Context, f ParentLimitsCase) {
	sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.Token})
	rootRequest := func() map[string]any { return map[string]any{"person": map[string]any{}, "audience": f.Root} }
	ask := []any{scopeAsk(f.Kind, []string{f.Action}, []string{f.ResourceID})}
	hopRequest := func(parent protoreflect.Message, h Hop) map[string]any {
		return map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": h.Credential}, "audience": h.Audience, "operation_binding_id": h.Binding}
	}
	self := Hop{Credential: f.Credential, Audience: f.Root, Binding: f.SelfBinding}
	t.Run("action-specific resources", func(t *testing.T) {
		req := rootRequest()
		req["scopes"] = []any{
			scopeAsk(f.Kind, []string{f.Action}, []string{f.ResourceID}),
			scopeAsk(f.Kind, []string{f.DroppedAction}, []string{f.OtherResourceID}),
		}
		parent := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", req)
		for n := 0; n < 4; n++ {
			if n > 0 {
				intermediate := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", hopRequest(parent, f.Out))
				parent = c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", hopRequest(intermediate, f.Back))
			}
			c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(parent, "token"), "audience": f.Root})
			for _, pair := range [][3]string{{f.Action, f.ResourceID, f.OtherResourceID}, {f.DroppedAction, f.OtherResourceID, f.ResourceID}} {
				listed := c.must(t, ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{
					"token": str(parent, "token"), "audience": f.Root, "resource_kind": f.Kind, "action": pair[0],
				})
				matcher, err := resources.Compile(grantsOf(listed))
				if err != nil {
					t.Fatal(err)
				}
				if !matcher.Matches(pair[1]) || matcher.Matches(pair[2]) || matcher.All() {
					t.Fatalf("%s must grant only %s, not %s", pair[0], pair[1], pair[2])
				}
			}
		}
	})
	for _, where := range []string{"root", "child"} {
		t.Run(where, func(t *testing.T) {
			req := rootRequest()
			if where == "root" {
				req["scopes"] = ask
			}
			parent := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", req)
			if where == "child" {
				req = hopRequest(parent, self)
				req["scopes"] = ask
				parent = c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", req)
			}
			for range 4 {
				intermediate := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", hopRequest(parent, f.Out))
				if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{"token": str(intermediate, "token"), "audience": f.Out.Audience, "resource_kind": f.Kind, "action": f.Action}); status.Code(err) != codes.PermissionDenied {
					t.Fatalf("carried cap is usable at the wrong target: %v", err)
				}
				parent = c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", hopRequest(intermediate, f.Back))
				exactEffectiveScope(t, msg(parent, "context"), f.Kind, []string{f.Action}, []string{f.ResourceID})
				c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(parent, "token"), "audience": f.Root})
				for _, forbidden := range []map[string]any{
					scopeAsk(f.Kind, []string{f.DroppedAction}, []string{f.ResourceID}),
					scopeAsk(f.Kind, []string{f.Action}, []string{f.OtherResourceID}),
					scopeAsk(f.DroppedKind, []string{f.Action}, nil),
				} {
					req := hopRequest(parent, self)
					req["scopes"] = []any{forbidden}
					if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied {
						t.Fatalf("parent restriction recovered for %v: %v", forbidden, err)
					}
				}
			}
		})
	}
}
