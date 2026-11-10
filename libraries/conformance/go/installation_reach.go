package conformance

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Consent covers reach. What a role on a solution reaches through the
// solution's bindings (ReviewedOffer roles' reach) is part of what an
// administrator approves: the approval names its digest (reach_digest). A
// delivery of a module the solution reaches that lets the role do more (a
// method policy relaxed) offers the solution's installation an upgrade,
// though the solution did not change; until an administrator approves it,
// the holder reads, and holds, the approved reach, and so does the
// installation's own agent: the newly admitted operation is refused to both
// through the solution. A fresh Review and Install
// approves the wider reach on the same installation.
const (
	reachSolution = "conformance-reach"
	reachStore    = "conformance-reach-store"
	reachItem     = reachStore + ".item"
	reachGet      = "/conformance.reach.Store/Get"
	reachPurge    = "/conformance.reach.Store/Purge"
)

func (c *client) reachConsent(t *testing.T, ctx context.Context, f Fixture) {
	c.run(t, f, "consent covers what a role reaches through the solution", func(t *testing.T, c *client, f Fixture) {
		if f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" {
			t.Fatal("required conformance fixture missing: signed delivery, an administrator and a member holding no role (UnentitledToken)")
		}
		store := func(purge string) map[string]any {
			return map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(reachItem, []string{"admin", "read", "write"}, nil)},
				"methods": []any{
					map[string]any{"method": reachGet, "requires": []any{scopeAsk(reachItem, []string{"read"}, nil)}},
					map[string]any{"method": reachPurge, "requires": []any{scopeAsk(reachItem, []string{purge}, nil)}},
				}}
		}
		if _, err := c.deliver(ctx, f, reachStore, "module", 1, []string{reachItem}, store("admin"), 0); err != nil {
			t.Fatalf("deliver %s: %v", reachStore, err)
		}
		page := reachSolution + ".page"
		items := []any{scopeAsk(reachItem, []string{"read", "write"}, nil)}
		solution := map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(page, []string{"read"}, nil)}, "roles": []any{
			map[string]any{"name": "installer", "scopes": append([]any{scopeAsk(page, []string{"read"}, nil)}, items...)},
			map[string]any{"name": "editor", "scopes": append([]any{scopeAsk(page, []string{"read"}, nil)}, items...)},
		}}
		binding := solutionhost.AuthorityBinding{ID: "store", Audience: reachStore, Operations: map[string][]string{"invoke": {reachItem + ":read", reachItem + ":write"}}}
		if _, err := c.deliver(ctx, f, reachSolution, "solution", 1, []string{page}, solution, 0, binding); err != nil {
			t.Fatalf("deliver %s: %v", reachSolution, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		approval := c.reviewInstallation(t, adminCtx, f.Organization, reachSolution)
		if approval["reach_digest"] == "" {
			t.Fatal("the review names no reach_digest: the consent would not cover what the roles reach")
		}
		install := func(t *testing.T) protoreflect.Message {
			t.Helper()
			return c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{"organization_id": f.Organization, "target": reachSolution,
				"role": "installer", "owner_person_id": str(admin, "person_id"), "approval": c.reviewInstallation(t, adminCtx, f.Organization, reachSolution)})
		}
		id := str(install(t), "id")
		c.must(t, adminCtx, "host.installation.v1.InstallationService", "GrantRole", map[string]any{"organization_id": f.Organization, "installation_id": id, "role": "editor", "person_id": str(holder, "person_id")})
		upgrade := func(t *testing.T) bool {
			t.Helper()
			for _, inst := range listMsgs(c.must(t, adminCtx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization}), "installations") {
				if str(inst, "id") == id {
					return field(inst, "upgrade_available").Bool()
				}
			}
			t.Fatalf("%s is not listed", id)
			return false
		}
		// reached is the operations the editor's reach lists at the store, as sess reviews it.
		reached := func(t *testing.T, sess protoreflect.Message) []string {
			t.Helper()
			out := c.must(t, as(ctx, sess), "host.installation.v1.OfferService", "ReviewOffer", map[string]any{"organization_id": f.Organization, "target": reachSolution})
			for _, r := range listMsgs(out, "roles") {
				if str(r, "name") != "editor" {
					continue
				}
				for _, row := range listMsgs(r, "reach") {
					if str(row, "module") == reachStore && str(row, "via") == "binding" {
						ops := listStrings(row, "operations")
						slices.Sort(ops)
						return ops
					}
				}
			}
			return nil
		}
		// call is the holder, through the solution's binding, calling method at the store.
		call := func(method string) error {
			root, err := c.call(as(ctx, holder), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": reachSolution, "operation_binding_id": "store"})
			if err != nil {
				return err
			}
			hop, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"),
				"actor": map[string]any{"credential": f.DeliveryCredential(reachSolution)}, "operation_binding_id": "store", "audience": reachStore})
			if err != nil {
				return err
			}
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(hop, "token"), "audience": reachStore, "method": method})
			return err
		}
		// agentCall is the installation's own agent (installer) calling method
		// at the store through the solution's binding.
		agentCall := func(method string) error {
			at, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"installation": map[string]any{"installation_id": id},
				"actor": map[string]any{"credential": f.DeliveryCredential(reachSolution)}, "audience": reachStore, "operation_binding_id": "store"})
			if err != nil {
				return err
			}
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(at, "token"), "audience": reachStore, "method": method})
			return err
		}
		if f.ReviewOfferNotServed == "" {
			if got := reached(t, admin); !slices.Equal(got, []string{reachGet}) {
				t.Fatalf("the editor reaches %v at the store, want [%s]", got, reachGet)
			}
		}
		if upgrade(t) {
			t.Fatal("a fresh installation offers an upgrade")
		}
		if err := call(reachGet); err != nil {
			t.Fatalf("the approved reach is refused: %v", err)
		}
		refused(t, call(reachPurge), codes.PermissionDenied, "")

		t.Run("a module's redelivery that widens a solution's reach offers an upgrade; holders keep the approved reach", func(t *testing.T) {
			if _, err := c.deliver(ctx, f, reachStore, "module", 2, []string{reachItem}, store("write"), 0); err != nil {
				t.Fatalf("redeliver %s relaxing Purge: %v", reachStore, err)
			}
			if !upgrade(t) {
				t.Fatal("the store relaxing a method the editor reaches offers the solution's installation no upgrade")
			}
			if f.ReviewOfferNotServed == "" {
				if got := reached(t, holder); !slices.Equal(got, []string{reachGet}) {
					t.Fatalf("the holder reads the reach %v at the store, want the approved [%s]", got, reachGet)
				}
				if got := reached(t, admin); !slices.Equal(got, []string{reachGet, reachPurge}) {
					t.Fatalf("the administrator reviews the reach %v at the store, want the delivered one", got)
				}
			}
			if err := call(reachGet); err != nil {
				t.Fatalf("the approved reach is refused while an upgrade is pending: %v", err)
			}
			refused(t, call(reachPurge), codes.PermissionDenied, "approved")
			if err := agentCall(reachGet); err != nil {
				t.Fatalf("the agent's approved reach is refused while an upgrade is pending: %v", err)
			}
			refused(t, agentCall(reachPurge), codes.PermissionDenied, "approved")
			_, err := c.call(adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{"organization_id": f.Organization, "target": reachSolution,
				"role": "installer", "owner_person_id": str(admin, "person_id"), "approval": approval})
			refused(t, err, codes.FailedPrecondition, "INSTALLATION_APPROVAL_")
		})
		t.Run("a fresh review and Install approve the wider reach on the same installation", func(t *testing.T) {
			if got := str(install(t), "id"); got != id {
				t.Fatalf("the upgrade made another installation %s", got)
			}
			if upgrade(t) {
				t.Fatal("an upgrade is still offered once approved")
			}
			if err := call(reachPurge); err != nil {
				t.Fatalf("the approved wider reach is refused: %v", err)
			}
			if err := agentCall(reachPurge); err != nil {
				t.Fatalf("the approved wider reach is refused to the agent: %v", err)
			}
		})
	})
}
