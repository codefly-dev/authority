package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// An installation survives the delivery of its target. A redelivery that asks
// nothing new of the organization (no role, binding, edge dependency or
// method added, none reaching further, no standing authority asked)
// re-converges the installation without a click: it stays active, its
// approved generation advances, its grants stay, and what was issued under
// the earlier generation ends. A redelivery that asks more leaves the
// installation on its consent, active with its grants, and offers an upgrade
// (Installation.upgrade_available), which an administrator approves with a
// fresh Review and Install on the same installation: no uninstall, grants
// kept. An install never deletes a role grant.
const (
	redeliveredSolution = "conformance-redelivered"
	redeliveredPage     = redeliveredSolution + ".page"
	redeliveredDraft    = redeliveredSolution + ".draft"
)

func (c *client) installationSurvivesDelivery(t *testing.T, ctx context.Context, f Fixture) {
	t.Run("an installation survives delivery", func(t *testing.T) {
		if f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" {
			t.Fatal("required conformance fixture missing: signed delivery, an administrator and a member holding no role (UnentitledToken)")
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		kinds := []string{redeliveredPage, redeliveredDraft}
		all := []any{scopeAsk(redeliveredPage, []string{"read", "write"}, nil), scopeAsk(redeliveredDraft, []string{"read", "write"}, nil)}
		installer := map[string]any{"name": "installer", "scopes": all}
		deliver := func(generation uint64, roles ...any) {
			t.Helper()
			document := map[string]any{"scope_ceilings": all, "roles": append([]any{installer}, roles...), "owner_aware": true}
			if _, err := c.deliver(ctx, f, redeliveredSolution, "solution", generation, kinds, document, 0); err != nil {
				t.Fatalf("deliver %s at %d: %v", redeliveredSolution, generation, err)
			}
		}
		listed := func(t *testing.T) protoreflect.Message {
			t.Helper()
			for _, inst := range listMsgs(c.must(t, adminCtx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization}), "installations") {
				if str(inst, "target") == redeliveredSolution {
					return inst
				}
			}
			t.Fatalf("%s is not installed at %s", redeliveredSolution, f.Organization)
			return nil
		}
		install := func(t *testing.T) (protoreflect.Message, error) {
			t.Helper()
			return c.call(adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{"organization_id": f.Organization, "target": redeliveredSolution,
				"role": "viewer", "owner_person_id": str(admin, "person_id"), "approval": c.reviewInstallation(t, adminCtx, f.Organization, redeliveredSolution)})
		}
		grants := func(t *testing.T, id string) int {
			t.Helper()
			return len(listMsgs(c.must(t, adminCtx, "host.installation.v1.InstallationService", "ListRoleGrants", map[string]any{"organization_id": f.Organization, "installation_id": id}), "grants"))
		}
		issue := func() (protoreflect.Message, error) {
			return c.call(as(ctx, holder), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": redeliveredSolution})
		}
		check := func(capability protoreflect.Message) error {
			_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(capability, "token"), "audience": redeliveredSolution})
			return err
		}
		stands := func(t *testing.T, inst protoreflect.Message, approved uint64, upgrade bool) {
			t.Helper()
			if enumName(inst, "status") != "STATUS_ACTIVE" || u64(inst, "approved_generation") != approved || field(inst, "upgrade_available").Bool() != upgrade {
				t.Fatalf("the installation is %s at approved generation %d, upgrade available %t; want active at %d, %t",
					enumName(inst, "status"), u64(inst, "approved_generation"), field(inst, "upgrade_available").Bool(), approved, upgrade)
			}
		}

		viewer := map[string]any{"name": "viewer", "scopes": []any{scopeAsk(redeliveredPage, []string{"read"}, nil), scopeAsk(redeliveredDraft, []string{"read"}, nil)}}
		deliver(1, viewer)
		installed, err := install(t)
		if err != nil {
			t.Fatal(err)
		}
		id := str(installed, "id")
		stands(t, installed, 1, false)
		c.must(t, adminCtx, "host.installation.v1.InstallationService", "GrantRole", map[string]any{"organization_id": f.Organization, "installation_id": id, "role": "viewer", "person_id": str(holder, "person_id")})
		if grants(t, id) != 1 {
			t.Fatal("the viewer grant was not recorded")
		}
		held, err := issue()
		if err != nil {
			t.Fatal(err)
		}

		t.Run("a redelivery asking nothing new re-converges it and keeps its grants", func(t *testing.T) {
			narrower := map[string]any{"name": "viewer", "scopes": []any{scopeAsk(redeliveredPage, []string{"read"}, nil)}}
			deliver(2, narrower)
			inst := listed(t)
			stands(t, inst, 2, false)
			if str(inst, "id") != id || u64(inst, "revision") <= u64(installed, "revision") {
				t.Fatalf("the installation did not move with the delivery: %v", inst)
			}
			if grants(t, id) != 1 {
				t.Fatal("the redelivery changed the grants")
			}
			refused(t, check(held), codes.PermissionDenied, "")
			if held, err = issue(); err != nil {
				t.Fatalf("the holder is not issued under the re-converged consent: %v", err)
			}
			_, err := install(t)
			refused(t, err, codes.PermissionDenied, "already installed")
			if grants(t, id) != 1 {
				t.Fatal("a refused install changed the grants")
			}
		})
		t.Run("a redelivery asking more leaves it on its consent and offers an upgrade", func(t *testing.T) {
			editor := map[string]any{"name": "editor", "scopes": []any{scopeAsk(redeliveredPage, []string{"read", "write"}, nil)}}
			deliver(3, viewer, editor)
			inst := listed(t)
			stands(t, inst, 2, true)
			if grants(t, id) != 1 {
				t.Fatal("the widening changed the grants")
			}
			if err := check(held); err != nil {
				t.Fatalf("a widening ended what the standing consent issued: %v", err)
			}
			c.must(t, adminCtx, "host.installation.v1.InstallationService", "GrantRole", map[string]any{"organization_id": f.Organization, "installation_id": id, "role": "editor", "person_id": str(holder, "person_id")})
		})
		t.Run("a fresh review and Install upgrade it in place, grants kept", func(t *testing.T) {
			upgraded, err := install(t)
			if err != nil {
				t.Fatal(err)
			}
			if str(upgraded, "id") != id {
				t.Fatalf("the upgrade made another installation %s", str(upgraded, "id"))
			}
			stands(t, upgraded, 3, false)
			stands(t, listed(t), 3, false)
			if grants(t, id) != 2 {
				t.Fatal("the upgrade changed the grants")
			}
			refused(t, check(held), codes.PermissionDenied, "")
			if _, err := issue(); err != nil {
				t.Fatalf("the holder is not issued after the upgrade: %v", err)
			}
			_, err = install(t)
			refused(t, err, codes.PermissionDenied, "already installed")
		})
	})
}
