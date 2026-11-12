package conformance

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Consent covers the scopes a role names through a binding, never the
// operations they open. A solution's role naming, through its binding to a
// relay, scopes at a module the relay reaches is consented to as those
// scopes: a redelivery of that module that widens what the role reaches
// there within them, and so opens an operation the approved reach does not
// list, offers the solution's installation an upgrade. Until an
// administrator approves it the holder keeps the approved reach, and the
// newly opened operation is refused through the solution; a fresh Review
// and Install approves it on the same installation.
const (
	throughSolution = "conformance-through"
	throughRelay    = "conformance-through-relay"
	throughVault    = "conformance-through-vault"
	throughTurn     = throughRelay + ".turn"
	throughItem     = throughVault + ".item"
	throughGet      = "/conformance.through.Vault/Get"
	throughPut      = "/conformance.through.Vault/Put"
)

func (c *client) reachThroughConsent(t *testing.T, ctx context.Context, f Fixture) {
	c.run(t, f, "consent covers the scopes a role names through a binding, not the operations they open", func(t *testing.T, c *client, f Fixture) {
		if f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" {
			t.Fatal("required conformance fixture missing: signed delivery, an administrator and a member holding no role (UnentitledToken)")
		}
		get := map[string]any{"method": throughGet, "requires": []any{scopeAsk(throughItem, []string{"read"}, nil)}}
		put := map[string]any{"method": throughPut, "requires": []any{scopeAsk(throughItem, []string{"write"}, nil)}}
		vault := func(served []string, methods ...any) map[string]any {
			return map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(throughItem, served, nil)}, "methods": methods}
		}
		if _, err := c.deliver(ctx, f, throughVault, "module", 1, []string{throughItem}, vault([]string{"read"}, get), 0); err != nil {
			t.Fatalf("deliver %s: %v", throughVault, err)
		}
		toVault := solutionhost.AuthorityBinding{ID: "vault", Audience: throughVault, Operations: map[string][]string{"invoke": {throughItem + ":read", throughItem + ":write"}}}
		relay := map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(throughTurn, []string{"run"}, nil)}}
		if _, err := c.deliver(ctx, f, throughRelay, "module", 1, []string{throughTurn}, relay, 0, toVault); err != nil {
			t.Fatalf("deliver %s: %v", throughRelay, err)
		}
		page := throughSolution + ".page"
		role := func(name string) map[string]any {
			return map[string]any{"name": name, "scopes": []any{scopeAsk(page, []string{"read"}, nil), scopeAsk(throughTurn, []string{"run"}, nil)},
				"through": []any{map[string]any{"binding": "relay", "scopes": []any{scopeAsk(throughItem, []string{"read", "write"}, nil)}}}}
		}
		solution := map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(page, []string{"read"}, nil)}, "roles": []any{role("installer"), role("editor")}}
		toRelay := solutionhost.AuthorityBinding{ID: "relay", Audience: throughRelay, Operations: map[string][]string{"invoke": {throughTurn + ":run"}}}
		if _, err := c.deliver(ctx, f, throughSolution, "solution", 1, []string{page}, solution, 0, toRelay); err != nil {
			t.Fatalf("deliver %s: %v", throughSolution, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		install := func(t *testing.T) string {
			t.Helper()
			return str(c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{"organization_id": f.Organization, "target": throughSolution,
				"role": "installer", "owner_person_id": str(admin, "person_id"), "approval": c.reviewInstallation(t, adminCtx, f.Organization, throughSolution)}), "id")
		}
		id := install(t)
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
		// reached is the operations the editor's reach lists at the vault, as sess reviews it.
		reached := func(t *testing.T, sess protoreflect.Message) []string {
			t.Helper()
			out := c.must(t, as(ctx, sess), "host.installation.v1.OfferService", "ReviewOffer", map[string]any{"organization_id": f.Organization, "target": throughSolution})
			for _, r := range listMsgs(out, "roles") {
				if str(r, "name") != "editor" {
					continue
				}
				for _, row := range listMsgs(r, "reach") {
					if str(row, "module") == throughVault && str(row, "via") == "binding" {
						ops := listStrings(row, "operations")
						slices.Sort(ops)
						return ops
					}
				}
			}
			return nil
		}
		// call is the holder, through the solution's binding to the relay and
		// the relay's to the vault, calling method at the vault.
		call := func(method string) error {
			root, err := c.call(as(ctx, holder), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": throughSolution, "operation_binding_id": "relay"})
			if err != nil {
				return err
			}
			atRelay, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"),
				"actor": map[string]any{"credential": f.DeliveryCredential(throughSolution)}, "operation_binding_id": "relay", "audience": throughRelay})
			if err != nil {
				return err
			}
			atVault, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(atRelay, "token"),
				"actor": map[string]any{"credential": f.DeliveryCredential(throughRelay)}, "operation_binding_id": "vault", "audience": throughVault})
			if err != nil {
				return err
			}
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(atVault, "token"), "audience": throughVault, "method": method})
			return err
		}
		if upgrade(t) {
			t.Fatal("a fresh installation offers an upgrade")
		}
		if err := call(throughGet); err != nil {
			t.Fatalf("the approved reach through the relay is refused: %v", err)
		}

		t.Run("a redelivery opening an operation within the consented scopes offers an upgrade; holders keep the approved reach", func(t *testing.T) {
			if _, err := c.deliver(ctx, f, throughVault, "module", 2, []string{throughItem}, vault([]string{"read", "write"}, get, put), 0); err != nil {
				t.Fatalf("redeliver %s serving write: %v", throughVault, err)
			}
			if !upgrade(t) {
				t.Fatal("the vault opening Put within what the editor names through the relay offers the solution's installation no upgrade")
			}
			if f.ReviewOfferNotServed == "" {
				if got := reached(t, holder); !slices.Equal(got, []string{throughGet}) {
					t.Fatalf("the holder reads the reach %v at the vault, want the approved [%s]", got, throughGet)
				}
				if got := reached(t, admin); !slices.Equal(got, []string{throughGet, throughPut}) {
					t.Fatalf("the administrator reviews the reach %v at the vault, want the delivered one", got)
				}
			}
			if err := call(throughGet); err != nil {
				t.Fatalf("the approved reach is refused while an upgrade is pending: %v", err)
			}
			refused(t, call(throughPut), codes.PermissionDenied, "")
		})
		t.Run("a fresh review and Install approve the opened operation on the same installation", func(t *testing.T) {
			if got := install(t); got != id {
				t.Fatalf("the upgrade made another installation %s", got)
			}
			if upgrade(t) {
				t.Fatal("an upgrade is still offered once approved")
			}
			if err := call(throughPut); err != nil {
				t.Fatalf("the approved operation is refused: %v", err)
			}
		})
	})
}
