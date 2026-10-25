package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
)

func (c *client) bindingRefusals(t *testing.T, ctx context.Context, f Fixture) {
	for _, tc := range []struct {
		name, binding, audience, action, reason string
		code                                    codes.Code
	}{
		{"a child naming an undeclared binding is refused by name", "undeclared", f.BindingAudience, "read", "undeclared", codes.NotFound},
		{"a child naming the wrong binding audience is refused by name", f.Binding, f.Elsewhere, "read", "addressed", codes.PermissionDenied},
		{"a child naming no binding is refused by name", "", f.BindingAudience, "read", "names the binding", codes.PermissionDenied},
		{"a child widening its owner's current binding grants is refused by name", f.Binding, f.BindingAudience, "conformance-unheld", "widens", codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
			root := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.WorkloadModule, "operation_binding_id": f.Binding})
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"), "actor": map[string]any{"credential": f.WorkloadCredential}, "operation_binding_id": tc.binding, "audience": tc.audience, "scopes": []any{scopeAsk(f.ReadKind, []string{tc.action}, nil)}})
			refused(t, err, tc.code, tc.reason)
		})
	}
}

func (c *client) resourceMethod(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("a resource limited scope cannot authorize a whole kind method", func(t *testing.T) {
		if f.Resources == nil || len(f.Resources.Covered) == 0 || f.SignManifest == nil || f.SignAuthority == nil {
			t.Fatal("required conformance fixture missing: resources and signed method policy")
		}
		r := *f.Resources
		const target = "conformance-methods"
		const method = "/conformance.Service/WholeKind"
		if _, err := c.deliverWithMethods(ctx, f, target, 4, []string{r.Kind}, []any{map[string]any{"method": method, "requires": []any{scopeAsk(r.Kind, []string{r.Action}, nil)}}}, 0); err != nil {
			t.Fatal(err)
		}
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": r.Token})
		out := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": target, "scopes": []any{scopeAsk(r.Kind, []string{r.Action}, []string{r.Covered[0]})}})
		_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": target, "method": method})
		refused(t, err, codes.PermissionDenied, "requires")
	})
}
