package conformance

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InstallationChainCase starts at an installed solution, then follows at least
// two module bindings. Its selected role grants each hop's kind/action.
// Source is the solution principal; Credential authenticates that workload.
type InstallationChainCase struct {
	Installation, Source, Credential string
	Hops                             []Hop
}

func (c *client) installationChain(t *testing.T, ctx context.Context, f InstallationChainCase) {
	if f.Installation == "" || f.Source == "" || f.Credential == "" || len(f.Hops) < 2 {
		t.Fatal("installation chain requires an installed source and at least two hops")
	}
	parent := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
		"installation": map[string]any{"installation_id": f.Installation},
		"actor":        map[string]any{"credential": f.Credential}, "audience": f.Source,
	})
	root := msg(parent, "context")
	if str(root, "owner_principal_kind") != "agent" || len(listMsgs(root, "actor_chain")) != 0 {
		t.Fatalf("installation root is not owned by its agent: %v", root)
	}
	for n, hop := range f.Hops {
		before := msg(parent, "context")
		out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
			"parent_token": str(parent, "token"), "actor": map[string]any{"credential": hop.Credential},
			"audience": hop.Audience, "operation_binding_id": hop.Binding,
			"scopes": []any{scopeAsk(hop.AskKind, []string{hop.AskAction}, nil)},
		})
		wc := msg(out, "context")
		actors := listMsgs(wc, "actor_chain")
		if str(wc, "owner_principal_id") != str(root, "owner_principal_id") ||
			str(wc, "owner_principal_kind") != "agent" || str(wc, "owner_agent_id") != str(root, "owner_agent_id") ||
			str(wc, "tenant_id") != str(root, "tenant_id") || str(wc, "task_id") != str(root, "task_id") ||
			str(wc, "parent_session_id") != str(before, "session_id") || str(wc, "audience") != hop.Audience ||
			i64(wc, "expires_at_unix") > i64(before, "expires_at_unix") || len(actors) != n+1 {
			t.Fatalf("hop %d lost installation provenance: %v", n+1, wc)
		}
		for a, actor := range actors {
			want := f.Source
			if a > 0 {
				want = f.Hops[a-1].Audience
			}
			if str(actor, "principal_id") != want {
				t.Fatalf("hop %d actor %d: %v", n+1, a, actor)
			}
		}
		exactScope(t, wc, "authority_scopes", hop.AskKind, []string{hop.AskAction}, nil)
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": hop.Audience})
		parent = out
	}
	last := f.Hops[len(f.Hops)-1]
	// The previous actor cannot reuse a child now addressed to the next module.
	_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{
		"parent_token": str(parent, "token"), "actor": map[string]any{"credential": last.Credential},
		"audience": last.Audience, "operation_binding_id": last.Binding,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("installation child accepted the wrong actor: %v", err)
	}
}
