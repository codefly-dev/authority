package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Admission errors distinguish an absent installation from a person who cannot
// use an installed audience. Navigation must not need an administrative List.
func (c *client) admissionStatus(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("installation inventory is an administrator read", func(t *testing.T) {
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		for _, tc := range []struct {
			name string
			ctx  context.Context
			org  string
			want codes.Code
		}{
			{"anonymous", ctx, f.Organization, codes.Unauthenticated},
			{"viewer", as(ctx, viewer), f.Organization, codes.PermissionDenied},
			{"admin", as(ctx, admin), f.Organization, codes.OK},
			{"foreign organization", as(ctx, admin), "conformance-another-org", codes.PermissionDenied},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := c.call(tc.ctx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": tc.org})
				if status.Code(err) != tc.want {
					t.Fatalf("want %s, got %v", tc.want, err)
				}
			})
		}
	})
	t.Run("an uninstalled audience is a failed precondition", func(t *testing.T) {
		const target = "conformance-uninstalled"
		if _, err := c.applyManifest(ctx, f, target, "solution", 1, []string{"conformance.uninstalled"}); err != nil {
			t.Fatal(err)
		}
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		_, err := c.call(as(ctx, viewer), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": target})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("uninstalled audience: %v", err)
		}
	})
	t.Run("a person without grants cannot use an installed audience", func(t *testing.T) {
		if f.UnentitledToken == "" {
			t.Skip("fixture supplies no person without roles or teams")
		}
		person := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		_, err := c.call(as(ctx, person), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("unentitled person: %v", err)
		}
	})
}
