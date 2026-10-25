package conformance

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
)

// Admission errors distinguish an absent installation from a person who cannot
// use an installed audience. Navigation must not need an administrative List.
func (c *client) admissionStatus(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("installation inventory is an administrator read", func(t *testing.T) {
		t.Run("an organization owner can list installations", func(t *testing.T) {
			if f.OwnerToken == "" {
				t.Fatal("required conformance fixture missing: organization owner distinct from admin")
			}
			owner := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.OwnerToken})
			_, err := c.call(as(ctx, owner), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})
			refused(t, err, codes.OK, "")
		})
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
				reason := ""
				if tc.want == codes.PermissionDenied {
					reason = "owner"
					if tc.name == "foreign organization" {
						reason = "organization"
					}
				}
				refused(t, err, tc.want, reason)
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
		refused(t, err, codes.FailedPrecondition, fmt.Sprintf("audience %q is not installed in this organization, so there is no installation to seal the capability to", target))
	})
	t.Run("a person without grants cannot use an installed audience", func(t *testing.T) {
		if f.UnentitledToken == "" {
			t.Fatal("required conformance fixture missing: person without roles or teams")
		}
		person := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		_, err := c.call(as(ctx, person), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Audience})
		refused(t, err, codes.PermissionDenied, "the owner holds nothing at this audience")
	})
}
