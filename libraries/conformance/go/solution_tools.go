package conformance

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

// SolutionToolsCase is a module binding to an installed solution. Token holds
// a role on the solution that grants Action; Outsider holds none there. A
// person naming the module's binding is issued what their role on the
// solution holds through it, for the module's hop there, and nothing of the
// module's own: so Token reaches the solution through the module and
// Outsider is refused, at the binding and at every hop. Method is a delivered
// solution method requiring that action.
type SolutionToolsCase struct {
	Token, Outsider, Module, Credential, Binding, Audience, Kind, Action, Method string
}

func (c *client) solutionTools(t *testing.T, ctx context.Context, fixture Fixture, f SolutionToolsCase) {
	// Under the solution-principal contract a person reaches the solution's
	// data as its principal's: the ask is owner-selected.
	owner := c.solutionOwner(t, ctx, fixture, f.Audience)
	for _, token := range []string{f.Token, f.Outsider} {
		sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": token})
		read := []any{ownedBy(map[string]any{"resource_kind": f.Kind, "actions": []any{f.Action}}, owner)}
		// Row 15 proves the binding contributes its scope to person issuance.
		root, err := c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Module, "operation_binding_id": f.Binding})
		if token == f.Outsider {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("unentitled person binding: %v", err)
			}
			// With no role on the solution the binding carries nothing. A
			// module declaring no roles then gives them no capability at all
			// to hop with; where the module is a page they hold a role on,
			// that capability still reaches nothing of the solution.
			root, err = c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": f.Module})
			if err != nil {
				refused(t, err, codes.PermissionDenied, "")
				continue
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if got := scopeActions(msg(root, "context"), f.Kind); got != f.Action {
				t.Fatalf("binding scope = %q, want %q", got, f.Action)
			}
		}
		// Empty means the effective grant, not permission to address an
		// unentitled solution with unrelated inherited module scopes.
		unasked, unaskedErr := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"), "actor": map[string]any{"credential": f.Credential}, "operation_binding_id": f.Binding, "audience": f.Audience})
		if token == f.Outsider {
			if status.Code(unaskedErr) != codes.PermissionDenied {
				t.Fatalf("unentitled empty-ask child: %v", unaskedErr)
			}
		} else {
			if unaskedErr != nil {
				t.Fatal(unaskedErr)
			}
			c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(unasked, "token"), "audience": f.Audience, "method": f.Method})
		}
		child, err := c.call(ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"), "actor": map[string]any{"credential": f.Credential}, "operation_binding_id": f.Binding, "audience": f.Audience, "scopes": read})
		if token == f.Outsider {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("unentitled child: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		wc := msg(child, "context")
		actors := listMsgs(wc, "actor_chain")
		if str(wc, "owner_principal_id") != str(sess, "person_id") || str(wc, "owner_principal_kind") != "human" || len(actors) != 1 || str(actors[0], "principal_id") != f.Module {
			t.Fatalf("child changed owner/actor: %v", wc)
		}
		c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(child, "token"), "audience": f.Audience, "method": f.Method})
	}
}
