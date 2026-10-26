package conformance

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// InstallationLifecycleCase pauses the host's real install acknowledgement.
// Resume must be idempotent. Revoke drives the host's existing uninstall path;
// the public interface intentionally has no administrative revoke RPC.
type InstallationLifecycleCase struct {
	Target, Credential, Kind, Team string
	PauseInstall                   func() (resume func())
	Revoke                         func(context.Context, string) error
}

func (c *client) installationIdentity(t *testing.T, ctx context.Context, f Fixture) {
	for _, tc := range []struct {
		name, id, credential, org, reason string
		code                              codes.Code
	}{
		// An absent installation answers as another organization's does: a
		// solution learns nothing of which organizations installed what.
		{"an installation issue verifies the installation exists", "conformance-missing-installation", f.InstalledCredential, "", "installation", codes.PermissionDenied},
		{"an installation issue authenticates the installed solution", f.InstalledSolution, f.WorkloadCredential, "", "installed solution", codes.PermissionDenied},
		{"an installation issue cannot name a different organization", f.InstalledSolution, f.InstalledCredential, "conformance-foreign-org", "organization", codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f.InstalledSolution == "" || f.InstalledCredential == "" {
				t.Fatal("required conformance fixture missing: active installed solution and its credential")
			}
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
				"installation": map[string]any{"installation_id": tc.id}, "actor": map[string]any{"credential": tc.credential}, "audience": f.InstalledAudience, "organization_id": tc.org,
			})
			refused(t, err, tc.code, tc.reason)
		})
	}
}

func (c *client) installationLifecycle(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("installation acknowledgement gates exposure and revocation ends authority", func(t *testing.T) {
		if f.Lifecycle == nil || f.Lifecycle.PauseInstall == nil || f.Lifecycle.Revoke == nil {
			t.Fatal("required conformance fixture missing: real install acknowledgement and revocation controls")
		}
		l := *f.Lifecycle
		if l.Target == "" || l.Credential == "" || l.Team == "" {
			t.Fatal("required conformance fixture incomplete: installation lifecycle")
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		if _, err := c.applyManifest(ctx, f, l.Target, "solution", 1, []string{l.Kind}); err != nil {
			t.Fatal(err)
		}
		resume := l.PauseInstall()
		defer resume()
		type result struct {
			installation protoreflect.Message
			err          error
		}
		resultCh := make(chan result, 1)
		installCtx, cancel := context.WithTimeout(adminCtx, 10*time.Second)
		defer cancel()
		request := map[string]any{"organization_id": f.Organization, "target": l.Target, "role": "viewer", "owner_person_id": str(admin, "person_id")}
		go func() {
			inst, err := c.call(installCtx, "host.installation.v1.InstallationService", "Install", request)
			resultCh <- result{inst, err}
		}()
		var pending protoreflect.Message
		deadline := time.Now().Add(5 * time.Second)
		for pending == nil && time.Now().Before(deadline) {
			listed := c.must(t, adminCtx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization})
			for _, inst := range listMsgs(listed, "installations") {
				if str(inst, "target") == l.Target {
					pending = inst
					break
				}
			}
			if pending == nil {
				time.Sleep(10 * time.Millisecond)
			}
		}
		if pending == nil {
			t.Fatal("pending installation never became visible to its administrator")
		}
		id := str(pending, "id")
		issue := func() (protoreflect.Message, error) {
			return c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"installation": map[string]any{"installation_id": id}, "actor": map[string]any{"credential": l.Credential}, "audience": l.Target})
		}
		// Exposure is a team's role grant.
		grant := map[string]any{"organization_id": f.Organization, "installation_id": id, "team_id": l.Team, "role": "viewer"}
		const expose = "GrantRole"
		t.Run("pending installation cannot issue or be exposed", func(t *testing.T) {
			if enumName(pending, "status") != "STATUS_PENDING" {
				t.Fatal("installation became active before acknowledgement")
			}
			_, err := issue()
			// The installation is not installed yet: a state that may still
			// change, as the solution-principal target names it.
			refused(t, err, codes.FailedPrecondition, "pending")
			_, err = c.call(adminCtx, "host.installation.v1.InstallationService", expose, grant)
			refused(t, err, codes.FailedPrecondition, "pending")
		})
		resume()
		select {
		case installed := <-resultCh:
			if installed.err != nil {
				t.Fatalf("acknowledged install: %v", installed.err)
			}
		case <-installCtx.Done():
			t.Fatal("acknowledged install did not finish")
		}
		t.Run("acknowledged installation is exposed to its team", func(t *testing.T) {
			c.must(t, adminCtx, "host.installation.v1.InstallationService", expose, grant)
			listed := c.must(t, adminCtx, "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": id})
			if grants := listMsgs(listed, "grants"); len(grants) != 1 || str(grants[0], "team_id") != l.Team || str(grants[0], "role") != "viewer" {
				t.Fatalf("acknowledged installation was not granted to its team exactly once: %v", grants)
			}
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", request)
			refused(t, err, codes.PermissionDenied, "already installed")
			foreignGrant := clone(grant)
			foreignGrant["organization_id"] = "conformance-foreign-org"
			_, err = c.call(adminCtx, "host.installation.v1.InstallationService", expose, foreignGrant)
			refused(t, err, codes.PermissionDenied, "organization")
		})
		out, err := issue()
		if err != nil {
			t.Fatal(err)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": l.Target})
		t.Run("revoked installation refuses existing and fresh authority", func(t *testing.T) {
			if err := l.Revoke(ctx, id); err != nil {
				t.Fatal(err)
			}
			_, err := issue()
			refused(t, err, codes.FailedPrecondition, "revoked")
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": l.Target})
			refused(t, err, codes.PermissionDenied, "")
		})
	})
}
