package conformance

import (
	"context"
	"slices"
	"strings"
	"testing"

	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ChildScopesCase describes two different targets whose bindings and owner
// grants allow the stated actions. Start also declares the second target so
// the person can explicitly delegate both. Each Hop's AskAction is retained
// by the restricted delegation; DroppedAction is held at the second target but
// excluded by that delegation. OutsideKind belongs to the root, not either hop.
type ChildScopesCase struct {
	Chain                                      Chain
	FirstActions, NextActions                  []string
	OutsideKind, OutsideAction                 string
	ResourceID, OtherResourceID, DroppedAction string
}

func scopeAsk(kind string, actions, ids []string) map[string]any {
	values := func(ss []string) []any {
		out := make([]any, len(ss))
		for i, s := range ss {
			out[i] = s
		}
		return out
	}
	return map[string]any{"resource_kind": kind, "actions": values(actions), "resource_ids": values(ids)}
}

func exactScope(t *testing.T, wc protoreflect.Message, name, kind string, actions, ids []string) {
	t.Helper()
	scopes := listMsgs(wc, name)
	if len(scopes) != 1 || str(scopes[0], "resource_kind") != kind {
		t.Fatalf("%s is not exactly target %s: %v", name, kind, scopes)
	}
	for key, want := range map[string][]string{"actions": actions, "resource_ids": ids} {
		list := field(scopes[0], key).List()
		got := make([]string, list.Len())
		for n := range got {
			got[n] = list.Get(n).String()
		}
		want = slices.Clone(want)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s: got %v want %v", key, got, want)
		}
	}
}

func (c *client) childScopes(t *testing.T, ctx context.Context, f ChildScopesCase) {
	if len(f.Chain.Hops) != 2 || f.ResourceID == "" || f.OtherResourceID == "" || f.OtherResourceID == f.ResourceID ||
		f.DroppedAction == "" || !slices.Contains(f.NextActions, f.DroppedAction) {
		t.Fatal("child-scope fixture requires two hops and distinct resource IDs")
	}
	first, next := f.Chain.Hops[0], f.Chain.Hops[1]
	sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": f.Chain.Token})
	issue := func(req map[string]any) protoreflect.Message {
		return c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", req)
	}
	hopRequest := func(parent protoreflect.Message, h Hop) map[string]any {
		return map[string]any{"parent_token": str(parent, "token"), "actor": map[string]any{"credential": h.Credential},
			"audience": h.Audience, "operation_binding_id": h.Binding}
	}
	check := func(out protoreflect.Message, audience string) {
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": audience})
	}
	root := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Chain.Start})
	if !slices.Contains(strings.Split(scopeActions(msg(root, "context"), f.OutsideKind), ","), f.OutsideAction) {
		t.Fatal("the binding-excluded scope must actually be held by the root")
	}
	parent := root
	for n, h := range f.Chain.Hops {
		out := issue(hopRequest(parent, h))
		wc, before := msg(out, "context"), msg(parent, "context")
		actions := f.FirstActions
		if n == 1 {
			actions = f.NextActions
		}
		exactScope(t, wc, "authority_scopes", h.AskKind, actions, nil)
		actors := listMsgs(wc, "actor_chain")
		if len(actors) != n+1 || str(actors[0], "principal_id") != f.Chain.Start ||
			str(actors[n], "principal_id") != str(before, "audience") ||
			str(wc, "owner_principal_id") != str(sess, "person_id") ||
			str(wc, "tenant_id") != str(before, "tenant_id") || str(wc, "task_id") != str(before, "task_id") ||
			str(wc, "parent_session_id") != str(before, "session_id") ||
			i64(wc, "expires_at_unix") > i64(before, "expires_at_unix") {
			t.Fatalf("child lost verified provenance: %v", wc)
		}
		check(out, h.Audience)
		parent = out
	}
	forbidden := hopRequest(root, first)
	forbidden["scopes"] = []any{scopeAsk(f.OutsideKind, []string{f.OutsideAction}, nil)}
	if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", forbidden); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("root scope outside target binding admitted: %v", err)
	}
	d := c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "Delegate", map[string]any{
		"module": f.Chain.Start, "purpose": "conformance target projection", "scopes": []any{
			scopeAsk(first.AskKind, []string{first.AskAction}, nil),
			scopeAsk(next.AskKind, []string{next.AskAction}, []string{f.ResourceID}),
		}})
	delegated := issue(map[string]any{"delegation": map[string]any{"delegation_id": str(d, "delegation_id")},
		"actor": map[string]any{"credential": first.Credential}, "audience": first.Audience, "operation_binding_id": first.Binding})
	exactScope(t, msg(delegated, "context"), "authority_scopes", first.AskKind, []string{first.AskAction}, nil)
	req := hopRequest(delegated, next)
	out := issue(req)
	wc := msg(out, "context")
	exactScope(t, wc, "authority_scopes", next.AskKind, []string{next.AskAction}, []string{f.ResourceID})
	actors := listMsgs(wc, "actor_chain")
	if len(actors) != 2 || str(actors[0], "delegation_id") != str(d, "delegation_id") ||
		str(actors[0], "principal_id") != f.Chain.Start || str(actors[1], "principal_id") != first.Audience {
		t.Fatalf("child lost explicit delegation provenance: %v", wc)
	}
	for _, actor := range actors {
		exactScope(t, actor, "granted_scopes", next.AskKind, []string{next.AskAction}, []string{f.ResourceID})
	}
	check(out, next.Audience)
	listed := c.must(t, ctx, "host.authority.v1.AuthorityService", "ListResources", map[string]any{
		"token": str(out, "token"), "audience": next.Audience, "resource_kind": next.AskKind, "action": next.AskAction,
	})
	matcher, err := resources.Compile(grantsOf(listed))
	if err != nil {
		t.Fatal(err)
	}
	if !matcher.Matches(f.ResourceID) || matcher.Matches(f.OtherResourceID) || matcher.All() {
		t.Fatal("resource discovery lost the explicit delegation ceiling")
	}
	for _, ask := range []map[string]any{
		scopeAsk(next.AskKind, []string{f.DroppedAction}, []string{f.ResourceID}),
		scopeAsk(next.AskKind, []string{next.AskAction}, []string{f.OtherResourceID}),
		scopeAsk(next.AskKind, []string{next.AskAction}, nil),
	} {
		req["scopes"] = []any{ask}
		if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("delegation widening admitted for %v: %v", ask, err)
		}
	}
	c.must(t, as(ctx, sess), "host.authority.v1.AuthorityService", "RevokeDelegation", map[string]any{"delegation_id": str(d, "delegation_id")})
	if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": next.Audience}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("descendant survived revocation: %v", err)
	}
	delete(req, "scopes")
	if _, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked parent issued a fresh child: %v", err)
	}
}
