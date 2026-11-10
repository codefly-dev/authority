package conformance

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// One rule for every page, the one its backend is held to, on every host: a
// person's Issue naming page_target, made by the host's module edge (its own
// workload credential as the actor), is issued through the page's target's
// binding to the audience when the target declares one — the person's role on
// the target cut to the binding, its one actor the target as the person
// present on the page (kind "page") — and on the person's own access when the
// target declares none. Only the module edge names a page: the same Issue
// with no actor, or with any other workload's credential, is refused.
//
// A module page's role reaches a module that checks owners only as the page
// installation's own data, as a solution's role does: owner-selected to the
// principal of the page's composition installation, which its installation
// listing names; another owner is refused (RBAC-1). The suite delivers both
// audiences itself, one checking no owner (the ledger) and one checking owners
// (the store), so every host answers the same whatever its own fixture
// modules declare.
const (
	pageCallModule = "conformance-page-calls"
	pageCallNote   = pageCallModule + ".note"
	pageCallLedger = "conformance-page-ledger"
	pageLedgerKind = pageCallLedger + ".entry"
	pageCallStore  = "conformance-page-store"
	pageStoreKind  = pageCallStore + ".item"
	pageActorKind  = "page"
)

func (c *client) pageCalls(t *testing.T, ctx context.Context, f Fixture) {
	c.run(t, f, "a page's call goes through its target's binding, the person present, named by the module edge alone", func(t *testing.T, c *client, f Fixture) {
		if f.EdgeCredential == "" || f.WorkloadCredential == "" || f.SignManifest == nil || f.SignAuthority == nil || f.DeliveryCredential == nil || f.AdminToken == "" || f.UnentitledToken == "" || f.Elsewhere == "" {
			t.Fatal("required conformance fixture missing: the module edge's credential (EdgeCredential), a module's (WorkloadCredential), signed delivery, an administrator, a member holding no role (UnentitledToken) and a composed module the page declares no binding to (Elsewhere)")
		}
		for _, audience := range []struct {
			alias, kind string
			ownerAware  bool
		}{{pageCallLedger, pageLedgerKind, false}, {pageCallStore, pageStoreKind, true}} {
			document := map[string]any{"owner_aware": audience.ownerAware, "scope_ceilings": []any{scopeAsk(audience.kind, []string{"read", "write"}, nil)}}
			if _, err := c.deliver(ctx, f, audience.alias, "module", 1, []string{audience.kind}, document, 0); err != nil {
				t.Fatalf("deliver %s: %v", audience.alias, err)
			}
		}
		page := &solutionhost.Frontend{Title: "Conformance page calls", ExposedModule: "./Page", HostContract: 1, Payload: f.PagePayload}
		reach := []any{scopeAsk(pageLedgerKind, []string{"read"}, nil), scopeAsk(pageStoreKind, []string{"read"}, nil)}
		document := map[string]any{"scope_ceilings": []any{scopeAsk(pageCallNote, []string{"read", "write"}, nil)}, "installation_role": "none", "roles": []any{
			map[string]any{"name": "installer", "scopes": append([]any{scopeAsk(pageCallNote, []string{"read", "write"}, nil)}, reach...)},
			map[string]any{"name": "viewer", "scopes": append([]any{scopeAsk(pageCallNote, []string{"read"}, nil)}, reach...)},
		}}
		ledger := solutionhost.AuthorityBinding{ID: "ledger", Audience: pageCallLedger, Operations: map[string][]string{"invoke": {pageLedgerKind + ":read", pageLedgerKind + ":write"}}}
		store := solutionhost.AuthorityBinding{ID: "store", Audience: pageCallStore, Operations: map[string][]string{"invoke": {pageStoreKind + ":read"}}}
		if _, err := c.deliverPage(ctx, f, page, pageCallModule, "module", 1, []string{pageCallNote}, document, 0, ledger, store); err != nil {
			t.Fatalf("deliver %s with a page, roles and bindings to %s and %s: %v", pageCallModule, pageCallLedger, pageCallStore, err)
		}
		admin := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.AdminToken})
		var id, principal string
		for _, inst := range listMsgs(c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "List", map[string]any{"organization_id": f.Organization}), "installations") {
			if str(inst, "target") == pageCallModule && enumName(inst, "status") == "STATUS_ACTIVE" {
				id, principal = str(inst, "id"), str(inst, "principal_id")
			}
		}
		if id == "" {
			t.Fatalf("%s is not installed by composition", pageCallModule)
		}
		if principal == "" {
			t.Fatalf("%s's composition installation names no principal: what its page creates in a module that checks owners would be nobody's", pageCallModule)
		}
		holder := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.UnentitledToken})
		c.must(t, as(ctx, admin), "host.installation.v1.InstallationService", "GrantRole", map[string]any{
			"organization_id": f.Organization, "installation_id": id, "role": "viewer", "person_id": str(holder, "person_id")})
		issue := func(actor, audience string, scopes ...any) (protoreflect.Message, error) {
			fields := map[string]any{"person": map[string]any{}, "audience": audience, "page_target": pageCallModule}
			if actor != "" {
				fields["actor"] = map[string]any{"credential": actor}
			}
			if len(scopes) > 0 {
				fields["scopes"] = scopes
			}
			return c.call(as(ctx, holder), "host.authority.v1.AuthorityService", "Issue", fields)
		}
		out, err := issue(f.EdgeCredential, pageCallLedger)
		if err != nil {
			t.Fatalf("the viewer's page call at %s: %v", pageCallLedger, err)
		}
		chain := listMsgs(msg(out, "context"), "actor_chain")
		if len(chain) != 1 || str(chain[0], "principal_id") != pageCallModule || str(chain[0], "principal_kind") != pageActorKind {
			t.Fatalf("the page's call is the target's page hop, the person present: %v", chain)
		}
		granted := listMsgs(chain[0], "granted_scopes")
		if len(granted) != 1 || str(granted[0], "resource_kind") != pageLedgerKind || len(listStrings(granted[0], "actions")) != 1 || listStrings(granted[0], "actions")[0] != "read" {
			t.Fatalf("the viewer's role cut to the binding: %v", granted)
		}
		_, err = issue(f.EdgeCredential, pageCallLedger, scopeAsk(pageLedgerKind, []string{"write"}, nil))
		refused(t, err, codes.PermissionDenied, "widens")
		at, err := issue(f.EdgeCredential, pageCallStore)
		if err != nil {
			t.Fatalf("the viewer's page call at %s: %v", pageCallStore, err)
		}
		chain = listMsgs(msg(at, "context"), "actor_chain")
		if len(chain) != 1 {
			t.Fatalf("the page's call at %s is one page hop: %v", pageCallStore, chain)
		}
		granted = listMsgs(chain[0], "granted_scopes")
		if len(granted) != 1 || str(granted[0], "resource_kind") != pageStoreKind || str(granted[0], "resource_owner_id") != principal {
			t.Fatalf("at a module that checks owners the viewer's role is the page installation's data (owner %s): %v", principal, granted)
		}
		owned := func(owner string) any {
			return map[string]any{"resource_kind": pageStoreKind, "actions": []any{"read"}, "resource_owner_id": owner}
		}
		if _, err := issue(f.EdgeCredential, pageCallStore, owned(principal)); err != nil {
			t.Fatalf("the page installation's own data, asked by owner: %v", err)
		}
		for _, other := range []string{"6f1c9d2e-0000-5000-8000-000000000001", f.Organization} {
			_, err = issue(f.EdgeCredential, pageCallStore, owned(other))
			refused(t, err, codes.PermissionDenied, "widens")
		}
		_, err = issue(f.EdgeCredential, f.Elsewhere)
		if codeOf := status.Code(err); codeOf != codes.PermissionDenied {
			t.Fatalf("a module the target declares no binding to is on the person's own access, which holds nothing there: %v", err)
		}
		for _, actor := range []string{"", f.WorkloadCredential} {
			_, err := issue(actor, pageCallLedger)
			refused(t, err, codes.PermissionDenied, "module edge")
		}
	})
}
