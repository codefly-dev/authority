package conformance

import (
	"context"
	"github.com/google/uuid"
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
	// SetAdministrator changes AdminToken's live organization role without
	// ending its session or membership; true restores its original roles.
	SetAdministrator func(context.Context, bool) error
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
		if f.Lifecycle == nil || f.Lifecycle.PauseInstall == nil || f.Lifecycle.Revoke == nil || f.Lifecycle.SetAdministrator == nil {
			t.Fatal("required conformance fixture missing: real install acknowledgement, administrator role and revocation controls")
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
		request := map[string]any{"organization_id": f.Organization, "target": l.Target, "role": "viewer", "owner_person_id": str(admin, "person_id"), "approval": c.reviewInstallation(t, adminCtx, f.Organization, l.Target)}
		t.Run("administrator loss after review refuses apply", func(t *testing.T) {
			if err := l.SetAdministrator(ctx, false); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := l.SetAdministrator(ctx, true); err != nil {
					t.Error(err)
				}
			}()
			_, err := c.call(installCtx, "host.installation.v1.InstallationService", "Install", request)
			refused(t, err, codes.PermissionDenied, "administrator")
		})
		for _, tc := range []struct {
			field  string
			value  any
			reason string
		}{
			{"target_id", "unreviewed-target", "GENERATION_CHANGED"},
			{"generation", uint64(2), "GENERATION_CHANGED"},
			{"expected_revision", uint64(1), "REVISION_CHANGED"},
			{"digest", "sha256:unreviewed", "DIGEST_CHANGED"},
		} {
			bad := clone(request)
			approval := clone(request["approval"].(map[string]any))
			approval[tc.field] = tc.value
			bad["approval"] = approval
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", bad)
			refused(t, err, codes.FailedPrecondition, "INSTALLATION_APPROVAL_"+tc.reason)
		}
		missing := clone(request)
		delete(missing, "approval")
		_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", missing)
		refused(t, err, codes.FailedPrecondition, "INSTALLATION_APPROVAL_REQUIRED")
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
				select {
				case early := <-resultCh:
					t.Fatalf("install finished before a pending row was visible: %v", early.err)
				case <-time.After(10 * time.Millisecond):
				}
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
		t.Run("administrator loss before acknowledgement leaves no active authority", func(t *testing.T) {
			if err := l.SetAdministrator(ctx, false); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := l.SetAdministrator(ctx, true); err != nil {
					t.Error(err)
				}
			}()
			resume()
			select {
			case installed := <-resultCh:
				refused(t, installed.err, codes.PermissionDenied, "administrator")
			case <-installCtx.Done():
				t.Fatal("acknowledgement did not finish after administrator loss")
			}
			_, err := issue()
			refused(t, err, codes.FailedPrecondition, "pending")
			_, err = c.call(adminCtx, "host.installation.v1.InstallationService", expose, grant)
			refused(t, err, codes.PermissionDenied, "organization")
			_, err = c.call(adminCtx, "host.installation.v1.InstallationService", "Install", request)
			refused(t, err, codes.PermissionDenied, "administrator")
		})
		// Restoring the live administrator lets the unchanged, still-pending
		// approval resume; the refused acknowledgement created no active grant.
		installed := c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", request)
		if str(installed, "id") != id || enumName(installed, "status") != "STATUS_ACTIVE" {
			t.Fatalf("restored administrator did not resume the pending installation: %v", installed)
		}
		t.Run("acknowledged installation is exposed to its team", func(t *testing.T) {
			c.must(t, adminCtx, "host.installation.v1.InstallationService", expose, grant)
			listed := c.must(t, adminCtx, "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": id})
			if grants := listMsgs(listed, "grants"); len(grants) != 1 || str(grants[0], "team_id") != l.Team || str(grants[0], "role") != "viewer" {
				t.Fatalf("acknowledged installation was not granted to its team exactly once: %v", grants)
			}
			// Role grants do not change the installation consent revision.
			retried := c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", request)
			if str(retried, "id") != id {
				t.Fatal("unchanged approval retry created another installation")
			}
			foreignGrant := clone(grant)
			foreignGrant["organization_id"] = "conformance-foreign-org"
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", expose, foreignGrant)
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
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", request)
			refused(t, err, codes.FailedPrecondition, "INSTALLATION_APPROVAL_REVISION_CHANGED")
			_, err = issue()
			refused(t, err, codes.FailedPrecondition, "revoked")
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": l.Target})
			refused(t, err, codes.PermissionDenied, "")
		})
	})
}

func (c *client) reviewInstallation(t *testing.T, ctx context.Context, org, target string) map[string]any {
	t.Helper()
	a := c.must(t, ctx, "host.installation.v1.InstallationService", "Review", map[string]any{"organization_id": org, "target": target})
	return map[string]any{"target_id": str(a, "target_id"), "generation": u64(a, "generation"), "expected_revision": u64(a, "expected_revision"), "digest": str(a, "digest"), "operation_id": uuid.NewString()}
}
