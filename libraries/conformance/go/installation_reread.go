package conformance

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
)

// A host that learns to read a declaration field reads the delivery it holds
// as a different declaration than it composed from it. It reads that
// delivery again as the same generation (a re-read), never waiting for a new
// one: the installation stays active on its consent, its holders hold what
// was approved, the re-read is offered as an upgrade, and an administrator
// approves it with a fresh Review and Install. A different document at the
// held generation is still refused.
const (
	rereadSolution = "conformance-reread"
	rereadVault    = "conformance-reread-vault"
	rereadItem     = rereadVault + ".item"
	rereadGet      = "/conformance.reread.Vault/Get"
	rereadPut      = "/conformance.reread.Vault/Put"
)

// RereadCase is how the suite stands a host in for one that read less than
// it reads now.
type RereadCase struct {
	// Strand holds the composed declaration of module, a solution, at the
	// generation the host holds, as a host that did not read roles' through
	// declarations composed it from the same delivery: each role without what
	// it names through a binding, and no source recorded.
	Strand func(ctx context.Context, module string) error
	// Reread reads again every delivery the host holds, as the host does
	// when it starts.
	Reread func(ctx context.Context) error
}

func (c *client) installationReread(t *testing.T, ctx context.Context, f Fixture) {
	c.run(t, f, "a delivery read again with a field the host learned is a re-read of its generation", func(t *testing.T, c *client, f Fixture) {
		if f.Reread == nil || f.Reread.Strand == nil || f.Reread.Reread == nil || f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" {
			t.Fatal("required conformance fixture missing: a re-read (Reread), signed delivery, an administrator and a member holding no role (UnentitledToken)")
		}
		get := map[string]any{"method": rereadGet, "requires": []any{scopeAsk(rereadItem, []string{"read"}, nil)}}
		put := map[string]any{"method": rereadPut, "requires": []any{scopeAsk(rereadItem, []string{"write"}, nil)}}
		vault := map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(rereadItem, []string{"read", "write"}, nil)}, "methods": []any{get, put}}
		if _, err := c.deliver(ctx, f, rereadVault, "module", 1, []string{rereadItem}, vault, 0); err != nil {
			t.Fatalf("deliver %s: %v", rereadVault, err)
		}
		page := rereadSolution + ".page"
		toVault := solutionhost.AuthorityBinding{ID: "vault", Audience: rereadVault, Operations: map[string][]string{"invoke": {rereadItem + ":read", rereadItem + ":write"}}}
		deliver := func(through ...string) error {
			role := func(name string) map[string]any {
				return map[string]any{"name": name, "scopes": []any{scopeAsk(page, []string{"read"}, nil)},
					"through": []any{map[string]any{"binding": "vault", "scopes": []any{scopeAsk(rereadItem, through, nil)}}}}
			}
			solution := map[string]any{"owner_aware": true, "scope_ceilings": []any{scopeAsk(page, []string{"read"}, nil)}, "roles": []any{role("installer"), role("editor")}}
			_, err := c.deliver(ctx, f, rereadSolution, "solution", 1, []string{page}, solution, 0, toVault)
			return err
		}
		if err := deliver("read"); err != nil {
			t.Fatalf("deliver %s: %v", rereadSolution, err)
		}
		// As composed by a host that read no through: what an approval taken
		// now reviews, and what its holders hold.
		if err := f.Reread.Strand(ctx, rereadSolution); err != nil {
			t.Fatalf("strand %s: %v", rereadSolution, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		adminCtx := as(ctx, admin)
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		install := func(t *testing.T) string {
			t.Helper()
			return str(c.must(t, adminCtx, "host.installation.v1.InstallationService", "Install", map[string]any{"organization_id": f.Organization, "target": rereadSolution,
				"role": "installer", "owner_person_id": str(admin, "person_id"), "approval": c.reviewInstallation(t, adminCtx, f.Organization, rereadSolution)}), "id")
		}
		id := install(t)
		c.must(t, adminCtx, "host.installation.v1.InstallationService", "GrantRole", map[string]any{"organization_id": f.Organization, "installation_id": id, "role": "editor", "person_id": str(holder, "person_id")})
		stands := func(t *testing.T, upgrade bool) {
			t.Helper()
			for _, inst := range listMsgs(c.must(t, adminCtx, "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization}), "installations") {
				if str(inst, "id") != id {
					continue
				}
				if enumName(inst, "status") != "STATUS_ACTIVE" || u64(inst, "approved_generation") != 1 || field(inst, "upgrade_available").Bool() != upgrade {
					t.Fatalf("the installation is %s at approved generation %d, upgrade available %t; want active at 1, %t",
						enumName(inst, "status"), u64(inst, "approved_generation"), field(inst, "upgrade_available").Bool(), upgrade)
				}
				return
			}
			t.Fatalf("%s is not listed", id)
		}
		// call is the editor, through the solution's binding to the vault,
		// calling method there.
		call := func(method string) error {
			root, err := c.call(as(ctx, holder), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": rereadSolution, "operation_binding_id": "vault"})
			if err != nil {
				return err
			}
			atVault, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"),
				"actor": map[string]any{"credential": f.DeliveryCredential(rereadSolution)}, "operation_binding_id": "vault", "audience": rereadVault})
			if err != nil {
				return err
			}
			_, err = c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(atVault, "token"), "audience": rereadVault, "method": method})
			return err
		}
		stands(t, false)
		if call(rereadGet) == nil {
			t.Fatal("the editor reaches the vault through a role composed without its through")
		}

		t.Run("the re-read holds the approved reach and offers the upgrade", func(t *testing.T) {
			if err := f.Reread.Reread(ctx); err != nil {
				t.Fatalf("read the held deliveries again: %v", err)
			}
			stands(t, true)
			if call(rereadGet) == nil {
				t.Fatal("the re-read widened the editor's reach without an approval")
			}
			if err := f.Reread.Reread(ctx); err != nil {
				t.Fatalf("a second re-read: %v", err)
			}
			stands(t, true)
		})
		t.Run("an administrator approves the re-read on the same installation", func(t *testing.T) {
			if got := install(t); got != id {
				t.Fatalf("the upgrade installed %s, want the installation %s", got, id)
			}
			stands(t, false)
			if err := call(rereadGet); err != nil {
				t.Fatalf("the approved re-read does not reach the vault: %v", err)
			}
			if call(rereadPut) == nil {
				t.Fatal("the editor writes the vault, which no reading declares")
			}
		})
		t.Run("a different document at the held generation is still refused", func(t *testing.T) {
			if deliver("read", "write") == nil {
				t.Fatal("a different authority document at the held generation was applied")
			}
			if call(rereadPut) == nil {
				t.Fatal("the refused document widened the editor")
			}
			stands(t, false)
		})
	})
}
