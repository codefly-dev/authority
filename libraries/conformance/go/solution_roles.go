package conformance

import (
	"context"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// SolutionRoleCase is an installed solution whose viewer has no independent
// organization grant for ConsumedAction. Its signed viewer role grants that
// action through Binding. OwnActions is the full delivered served ceiling;
// ForbiddenAction is outside both the role and binding. The host seeds the
// installation and team entitlement, not a duplicate permission resolver.
type SolutionRoleCase struct {
	Solution, Credential, Token, Outsider, OwnKind                   string
	Binding, Audience, ConsumedKind, ConsumedAction, ForbiddenAction string
	OwnActions                                                       []string
	Generation                                                       uint64
}

func (c *client) solutionRoleCases(t *testing.T, ctx context.Context, f Fixture) {
	names := []string{
		"a delivered solution role grants authority at its own audience",
		"a solution viewer reaches a consumed module without an organization grant",
		"a solution binding root carries its delivered role grants",
		"a person with no solution role is refused with a reason",
		"a solution role cannot exceed the delivered binding ceiling",
		"a delivered solution route distinguishes requires from any checked caller",
		"a signed solution role cannot exceed the served manifest ceiling",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if f.SolutionRoles == nil || f.SignManifest == nil || f.SignAuthority == nil {
				t.Fatal("required conformance fixture missing: signed solution roles and installed viewer entitlement")
			}
			r := *f.SolutionRoles
			if r.Solution == "" || r.Credential == "" || r.Token == "" || r.Outsider == "" || r.ConsumedAction == "" || len(r.OwnActions) == 0 {
				t.Fatal("required conformance fixture incomplete: solution roles")
			}
			own := scopeAsk(r.OwnKind, r.OwnActions, nil)
			viewer := scopeAsk(r.OwnKind, []string{"read"}, nil)
			consumed := scopeAsk(r.ConsumedKind, []string{r.ConsumedAction}, nil)
			// Under the solution-principal contract every scope a person holds
			// through the solution is owned by its principal (RunSolutionPrincipalTarget).
			owner := c.solutionOwner(t, ctx, f, r.Solution)
			asked := ownedBy(scopeAsk(r.ConsumedKind, []string{r.ConsumedAction}, nil), owner)
			// Replaying the identical signed delivery is intentional: each behaviour
			// can run alone, and no earlier test's success is its precondition.
			bindings := []solutionhost.AuthorityBinding{{ID: r.Binding, Audience: r.Audience, Operations: map[string][]string{
				"invoke": {r.ConsumedKind + ":" + r.ConsumedAction},
			}}}
			doc := map[string]any{
				"scope_ceilings": []any{own},
				"roles": []any{
					map[string]any{"name": "installer", "scopes": []any{own, consumed}},
					map[string]any{"name": "editor", "scopes": []any{scopeAsk(r.OwnKind, []string{"read", "write"}, nil)}},
					map[string]any{"name": "viewer", "scopes": []any{viewer, consumed}},
				},
				"methods": []any{
					map[string]any{"method": "GET /items/{id}", "requires": []any{viewer}},
					map[string]any{"method": "POST /items/{id}", "requires": []any{scopeAsk(r.OwnKind, []string{"write"}, nil)}},
					map[string]any{"method": "GET /open/{path=**}", "any_checked_caller": true},
				},
			}
			if c.solutionPrincipal() {
				doc["owner_aware"] = true
			}
			if _, err := c.deliver(ctx, f, r.Solution, "solution", r.Generation, []string{r.OwnKind}, doc, 0, bindings...); err != nil {
				t.Fatalf("deliver solution roles and ceiling: %v", err)
			}
			sess := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": r.Token})
			person := func(audience, binding string, scopes []any) (protoreflect.Message, error) {
				return c.call(as(ctx, sess), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": audience, "operation_binding_id": binding, "scopes": scopes})
			}
			switch name {
			case names[0]:
				out, err := person(r.Solution, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				exactScopeOwnedBy(t, msg(out, "context"), r.OwnKind, []string{"read"}, nil, owner)
				c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": r.Solution})
			case names[1]:
				_, err := person(r.Audience, "", []any{asked})
				refused(t, err, codes.PermissionDenied, "beyond")
				root, err := person(r.Solution, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				out := c.must(t, ctx, "host.authority.v1.AuthorityService", "Issue", map[string]any{"parent_token": str(root, "token"), "actor": map[string]any{"credential": r.Credential}, "operation_binding_id": r.Binding, "audience": r.Audience, "scopes": []any{asked}})
				wc := msg(out, "context")
				exactScopeOwnedBy(t, wc, r.ConsumedKind, []string{r.ConsumedAction}, nil, owner)
				if str(wc, "owner_principal_id") != str(sess, "person_id") || str(wc, "tenant_id") != f.Organization || str(msg(wc, "operation_binding"), "binding_id") != f.Organization+"/"+r.Solution+"/"+r.Binding {
					t.Fatal("solution child lost owner, tenant or canonical binding identity")
				}
				c.must(t, ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(out, "token"), "audience": r.Audience})
			case names[2]:
				out, err := person(r.Solution, r.Binding, []any{asked})
				if err != nil {
					t.Fatal(err)
				}
				exactScopeOwnedBy(t, msg(out, "context"), r.ConsumedKind, []string{r.ConsumedAction}, nil, owner)
			case names[3]:
				outsider := c.must(t, ctx, "host.session.v1.SessionService", "SignIn", map[string]any{"fixture_token": r.Outsider})
				_, err := c.call(as(ctx, outsider), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": r.Solution})
				refused(t, err, codes.PermissionDenied, c.noRole())
				_, err = c.call(as(ctx, outsider), "host.authority.v1.AuthorityService", "Issue", map[string]any{"person": map[string]any{}, "audience": r.Solution, "operation_binding_id": r.Binding})
				refused(t, err, codes.PermissionDenied, c.noRole())
			case names[4]:
				_, err := person(r.Solution, r.Binding, []any{ownedBy(scopeAsk(r.ConsumedKind, []string{r.ForbiddenAction}, nil), owner)})
				refused(t, err, codes.PermissionDenied, "beyond")
				// A correctly signed role cannot manufacture an undeclared permission.
				doc["roles"] = []any{map[string]any{"name": "installer", "scopes": []any{own}}, map[string]any{"name": "viewer", "scopes": []any{scopeAsk(r.ConsumedKind, []string{r.ForbiddenAction}, nil)}}}
				_, err = c.deliver(ctx, f, r.Solution, "solution", r.Generation+1, []string{r.OwnKind}, doc, 0, bindings...)
				refused(t, err, codes.PermissionDenied, "role")
			case names[6]:
				doc["roles"] = []any{map[string]any{"name": "installer", "scopes": []any{own}}, map[string]any{"name": "viewer", "scopes": []any{scopeAsk(r.OwnKind, []string{"conformance-unheld"}, nil)}}}
				_, err := c.deliver(ctx, f, r.Solution, "solution", r.Generation+1, []string{r.OwnKind}, doc, 0, bindings...)
				refused(t, err, codes.PermissionDenied, "role")
			case names[5]:
				root, err := person(r.Solution, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				for _, route := range []struct {
					method string
					code   codes.Code
					reason string
				}{
					{"GET /items/one", codes.OK, ""}, {"POST /items/one", codes.PermissionDenied, "requires"},
					{"GET /open/a/b", codes.OK, ""}, {"GET /missing", codes.NotFound, "no method"},
				} {
					t.Run(route.method, func(t *testing.T) {
						_, err := c.call(ctx, "host.authority.v1.AuthorityService", "Check", map[string]any{"token": str(root, "token"), "audience": r.Solution, "method": route.method})
						refused(t, err, route.code, route.reason)
					})
				}
			}
		})
	}
}
