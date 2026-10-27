package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
)

func (c *client) currentInstallation(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("a module reads only its current installation", func(t *testing.T) {
		viewer := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.ViewerToken})
		parent := c.must(t, as(ctx, viewer), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.WorkloadModule})
		req := map[string]any{"parent_token": str(parent, "token"), "actor_credential": f.WorkloadCredential}
		current := c.must(t, ctx, "host.installation.v1.InstallationService", "Current", req)
		seal := msg(msg(parent, "context"), "seal")
		if str(current, "id") != str(seal, "installation_id") || str(current, "organization_id") != f.Organization || str(current, "namespace") == "" || str(current, "target") == "" {
			t.Fatalf("current installation differs from parent: %v", current)
		}
		for _, probe := range []struct {
			credential string
			code       codes.Code
		}{{"", codes.PermissionDenied}, {"forged", codes.PermissionDenied}, {f.InstalledCredential, codes.Unauthenticated}} {
			_, err := c.call(ctx, "host.installation.v1.InstallationService", "Current", map[string]any{"parent_token": str(parent, "token"), "actor_credential": probe.credential})
			refused(t, err, probe.code, "")
		}
		_, err := c.call(ctx, "host.installation.v1.InstallationService", "Current", map[string]any{"parent_token": "forged", "actor_credential": f.WorkloadCredential})
		refused(t, err, codes.Unauthenticated, "")
	})
}
