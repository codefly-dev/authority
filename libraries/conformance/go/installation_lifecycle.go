package conformance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// InstallationLifecycleCase pauses the host's real install acknowledgement.
// Resume must be idempotent. Revoke drives the host's existing uninstall path;
// the public interface intentionally has no administrative revoke RPC.
type InstallationLifecycleCase struct {
	Target, Credential, Kind, Team string
	PauseInstall                   func() (resume func())
	Revoke                         func(context.Context, string) error
	// Review reads the offered target and current revision through the host's
	// generated catalogue/list clients and returns its generated ConsentApproval.
	// The 0.2 interface has no shared catalogue or Review RPC.
	Review func(context.Context, string, string) (proto.Message, error)
}

func (c *client) installationIdentity(t *testing.T, ctx context.Context, f Fixture) {
	for _, tc := range []struct {
		name, id, credential, org, reason string
		code                              codes.Code
	}{
		{"an installation issue verifies the installation exists", "conformance-missing-installation", f.InstalledCredential, "", "installation", codes.NotFound},
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
		if f.Lifecycle == nil || f.Lifecycle.PauseInstall == nil || f.Lifecycle.Revoke == nil || f.Lifecycle.Review == nil {
			t.Fatal("required conformance fixture missing: reviewed consent, real install acknowledgement and revocation controls")
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
		reviewed, err := l.Review(adminCtx, f.Organization, l.Target)
		if err != nil {
			t.Fatalf("review installation: %v", err)
		}
		a := reviewed.ProtoReflect()
		approval := map[string]any{"target_id": str(a, "target_id"), "generation": u64(a, "generation"), "expected_revision": u64(a, "expected_revision"), "operation_id": uuid.NewString()}
		request := map[string]any{"organization_id": f.Organization, "target": l.Target, "role": "viewer", "owner_person_id": str(admin, "person_id"), "approval": approval}
		for _, tc := range []struct {
			field  string
			value  any
			reason string
		}{
			{"target_id", uuid.NewString(), "GENERATION_CHANGED"},
			{"generation", uint64(2), "GENERATION_CHANGED"},
			{"expected_revision", uint64(1), "REVISION_CHANGED"},
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
		_, err = c.call(adminCtx, "host.installation.v1.InstallationService", "Install", missing)
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
		grant := map[string]any{"organization_id": f.Organization, "installation_id": id, "team_id": l.Team}
		// Exposure is GrantToTeam before the solution-principal contract and a
		// team's role grant (GrantRole) under it, which deletes GrantToTeam.
		expose := "GrantToTeam"
		if c.solutionPrincipal() {
			expose = "GrantRole"
			grant["role"] = "viewer"
		}
		t.Run("pending installation cannot issue or be exposed", func(t *testing.T) {
			if enumName(pending, "status") != "STATUS_PENDING" {
				t.Fatal("installation became active before acknowledgement")
			}
			_, err := issue()
			refused(t, err, codes.PermissionDenied, "pending")
			_, err = c.call(adminCtx, "host.installation.v1.InstallationService", expose, grant)
			refused(t, err, codes.PermissionDenied, "pending")
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
		retried := c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", request)
		if str(retried, "id") != id {
			t.Fatal("unchanged approval retry created another installation")
		}
		t.Run("acknowledged installation is exposed to its team", func(t *testing.T) {
			exposed := c.must(t, adminCtx, "host.installation.v1.InstallationService", expose, grant)
			if c.solutionPrincipal() {
				listed := c.must(t, adminCtx, "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": id})
				if grants := listMsgs(listed, "grants"); len(grants) != 1 || str(grants[0], "team_id") != l.Team || str(grants[0], "role") != "viewer" {
					t.Fatalf("acknowledged installation was not granted to its team exactly once: %v", grants)
				}
			} else if enumName(exposed, "status") != "STATUS_ACTIVE" || count(exposed, "team_ids") != 1 || u64(exposed, "revision") != u64(pending, "revision")+1 {
				t.Fatal("acknowledged installation was not exposed exactly once")
			}
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", request)
			// In 0.2, team exposure advances the installation revision.
			refused(t, err, codes.FailedPrecondition, "INSTALLATION_APPROVAL_REVISION_CHANGED")
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
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", request)
			refused(t, err, codes.FailedPrecondition, "INSTALLATION_APPROVAL_REVISION_CHANGED")
			_, err = issue()
			refused(t, err, codes.PermissionDenied, "revoked")
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": l.Target})
			refused(t, err, codes.PermissionDenied, "")
		})
	})
}
