package issuer_test

import (
	"context"
	"errors"
	"maps"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

func solutionRoleKit(t *testing.T, roleScope *basev0.WorkScopeV1) (*testkit.Kit, state.Manifest) {
	t.Helper()
	k := testkit.New(t)
	m := testkit.Wiki(2)
	m.Bindings = map[string]state.Binding{
		"documents": {ID: "documents", Audience: "documents", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("documents", "read", "write")}},
		"directory": {ID: "directory", Audience: "org-directory", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("directory.entry", "read")}},
	}
	m.Roles["viewer"] = append(m.Roles["viewer"], roleScope, testkit.Scope("directory.entry", "read"))
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	return k, m
}

// Prepare parents and stored consent before an issuance-interleaving test starts.
func solutionPersonRequest(t *testing.T, k *testkit.Kit, who, path string, ask []*authorityv1.WorkScopeV1) (context.Context, *authorityv1.IssueRequest, error) {
	t.Helper()
	ctx := person(t, k, "fixture-"+who)
	req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "wiki"}
	if path == "binding" {
		req.OperationBindingId, req.Scopes = "documents", ask
		return ctx, req, nil
	}
	if path == "delegation" {
		d, err := k.Issuer.Delegate(ctx, "wiki", issuer.FromWire(ask), "solution role test")
		if err != nil {
			return nil, nil, err
		}
		return context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}, Audience: "documents", OperationBindingId: "documents", Scopes: ask}, nil
	}
	root, err := k.Issuer.Issue(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	actor := "wiki"
	if path == "later module" {
		root, err = k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}, OperationBindingId: "directory", Audience: "org-directory", Scopes: scopes(testkit.Scope("directory.entry", "read"))})
		if err != nil {
			return nil, nil, err
		}
		actor = "org-directory"
	}
	return context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, actor)}, OperationBindingId: "documents", Audience: "documents", Scopes: ask}, nil
}

func solutionPersonIssue(t *testing.T, k *testkit.Kit, who, path string, ask []*authorityv1.WorkScopeV1) (*authorityv1.IssueResponse, error) {
	t.Helper()
	ctx, req, err := solutionPersonRequest(t, k, who, path, ask)
	if err != nil {
		return nil, err
	}
	return k.Issuer.Issue(ctx, req)
}

func TestSolutionRoleIsThePermissionSourceForEveryPersonPath(t *testing.T) {
	for _, path := range []string{"binding", "child", "later module", "delegation"} {
		for _, tc := range []struct {
			who, role, ask string
			allowed        bool
		}{
			{"remi", "read", "read", true}, {"remi", "read", "write", false},
			{"maya", "write", "write", true},
		} {
			t.Run(path+"/"+tc.who+"/"+tc.ask, func(t *testing.T) {
				k, _ := solutionRoleKit(t, testkit.Scope("documents", tc.role))
				out, err := solutionPersonIssue(t, k, tc.who, path, scopes(testkit.Scope("documents", tc.ask)))
				if !tc.allowed {
					if err == nil {
						t.Fatalf("recovered organization write outside solution role: %v", out.Context)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := k.Issuer.Check(context.Background(), out.Token, out.Context.Audience, ""); err != nil {
					t.Fatal(err)
				}
				grants, err := k.Issuer.ListResources(context.Background(), out.Token, out.Context.Audience, "documents", tc.ask)
				if err != nil || !covered(t, grants).All() {
					t.Fatalf("unrestricted role lost resources: %v %v", grants, err)
				}
				if tc.who == "maya" {
					_, err := k.Issuer.Issue(person(t, k, "fixture-maya"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents", Scopes: scopes(testkit.Scope("documents", "write"))})
					if !errors.Is(err, issuer.ErrRefused) {
						t.Fatalf("solution role leaked into independent module access: %v", err)
					}
				}
			})
		}
	}
}

func TestSolutionBindingCannotBootstrapWithoutEntitlement(t *testing.T) {
	for _, path := range []string{"binding", "child", "later module", "delegation"} {
		for _, unavailable := range []string{"no team", "installation revoked", "other organization only"} {
			t.Run(path+"/"+unavailable, func(t *testing.T) {
				k, _ := solutionRoleKit(t, testkit.Scope("documents", "write"))
				who := "dev" // Keep the organisation union, but grant only finance below.
				if unavailable == "no team" {
					if err := k.State.Revoke(state.InstallationID("acme", "wiki")); err != nil {
						t.Fatal(err)
					}
					inst, err := k.State.Install(context.Background(), "acme", "wiki", "viewer", "alex")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := k.State.GrantToTeam(context.Background(), "acme", inst.ID, "finance"); err != nil {
						t.Fatal(err)
					}
				}
				if unavailable != "no team" {
					who = "remi"
					if err := k.State.Revoke(state.InstallationID("acme", "wiki")); err != nil {
						t.Fatal(err)
					}
					if unavailable == "installation revoked" {
						if err := k.State.Revoke(state.InstallationID("globex", "wiki")); err != nil {
							t.Fatal(err)
						}
					}
				}
				if out, err := solutionPersonIssue(t, k, who, path, scopes(testkit.Scope("documents", "write"))); err == nil {
					t.Fatalf("organization grant bootstrapped solution access: %v", out.Context)
				}
			})
		}
	}
}

func TestSolutionInstallationRevokesLaterPersonHops(t *testing.T) {
	for _, path := range []string{"binding", "child", "later module", "delegation"} {
		t.Run(path, func(t *testing.T) {
			k, _ := solutionRoleKit(t, testkit.Scope("documents", "write"))
			out, err := solutionPersonIssue(t, k, "maya", path, scopes(testkit.Scope("documents", "write")))
			if err != nil {
				t.Fatal(err)
			}
			if err := k.State.Revoke(state.InstallationID("acme", "wiki")); err != nil {
				t.Fatal(err)
			}
			if _, err := k.Issuer.Check(context.Background(), out.Token, out.Context.Audience, ""); err == nil {
				t.Fatal("person work survived source solution uninstall")
			}
			if _, err := k.Issuer.ListResources(context.Background(), out.Token, out.Context.Audience, "documents", "write"); err == nil {
				t.Fatal("resource read survived source solution uninstall")
			}
		})
	}
}

func TestSolutionRoleResourcesSurviveLaterHopsAndRevocation(t *testing.T) {
	for _, path := range []string{"child", "later module", "delegation"} {
		t.Run(path, func(t *testing.T) {
			held := testkit.Scope("documents", "write")
			held.ResourceIds = []string{"one"}
			k, m := solutionRoleKit(t, held)
			var issued *authorityv1.IssueResponse
			for _, tc := range []struct {
				ids     []string
				allowed bool
			}{{[]string{"one"}, true}, {[]string{"two"}, false}, {nil, false}} {
				out, err := solutionPersonIssue(t, k, "maya", path, []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}, ResourceIds: tc.ids}})
				if !tc.allowed {
					if err == nil {
						t.Fatalf("widened role resource IDs %v", tc.ids)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				grants, err := k.Issuer.ListResources(context.Background(), out.Token, "documents", "documents", "write")
				if err != nil {
					t.Fatal(err)
				}
				if got := covered(t, grants); !got.Matches("one") || got.Matches("two") || got.All() {
					t.Fatalf("role resources not preserved: %v", grants)
				}
				issued = out
			}
			m.Generation++
			m.Roles = maps.Clone(m.Roles)
			m.Roles["viewer"] = []*basev0.WorkScopeV1{testkit.Scope("wiki.page", "read"), testkit.Scope("directory.entry", "read")}
			if _, err := k.State.ApplyManifest(m); err != nil {
				t.Fatal(err)
			}
			if _, err := k.Issuer.Check(context.Background(), issued.Token, "documents", ""); !errors.Is(err, workcontext.ErrRevoked) {
				t.Fatalf("old role authority survived removal: %v", err)
			}
			if _, err := solutionPersonIssue(t, k, "maya", path, []*authorityv1.WorkScopeV1{{ResourceKind: "documents", Actions: []string{"write"}, ResourceIds: []string{"one"}}}); err == nil {
				t.Fatal("fresh work recovered removed role")
			}
		})
	}
}

func TestSolutionDelegationRechecksCurrentRoleAtUse(t *testing.T) {
	for _, change := range []string{"role narrowed", "delegation revoked"} {
		t.Run(change, func(t *testing.T) {
			k, m := solutionRoleKit(t, testkit.Scope("documents", "write"))
			ctx := person(t, k, "fixture-maya")
			d, err := k.Issuer.Delegate(ctx, "wiki", []*basev0.WorkScopeV1{testkit.Scope("documents", "write")}, "use-time validation")
			if err != nil {
				t.Fatal(err)
			}
			req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}, Audience: "documents", OperationBindingId: "documents", Scopes: scopes(testkit.Scope("documents", "write"))}
			before, err := k.Issuer.Issue(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if change == "role narrowed" {
				m.Generation++
				m.Roles = maps.Clone(m.Roles)
				m.Roles["viewer"] = []*basev0.WorkScopeV1{testkit.Scope("wiki.page", "read"), testkit.Scope("documents", "read")}
				if _, err := k.State.ApplyManifest(m); err != nil {
					t.Fatal(err)
				}
			} else if _, err := k.Issuer.RevokeDelegation(ctx, d.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := k.Issuer.Issue(context.Background(), req); err == nil {
				t.Fatal("stored consent recovered write")
			}
			if _, err := k.Issuer.Check(context.Background(), before.Token, "documents", ""); err == nil {
				t.Fatal("previously issued delegation survived revocation")
			}
		})
	}
}

func TestSolutionPersonRoleChangeCannotRaceIssuance(t *testing.T) {
	for _, path := range []string{"binding", "child", "later module", "delegation"} {
		for _, stage := range []string{"before_resolution", "before_mint", "during_mint", "after_issue"} {
			t.Run(path+"/"+stage, func(t *testing.T) {
				k, m := solutionRoleKit(t, testkit.Scope("documents", "write"))
				ctx, req, err := solutionPersonRequest(t, k, "maya", path, scopes(testkit.Scope("documents", "write")))
				if err != nil {
					t.Fatal(err)
				}
				issue := func() (*authorityv1.IssueResponse, error) { return k.Issuer.Issue(ctx, req) }
				if _, err := issue(); err != nil {
					t.Fatal(err)
				}
				out, err := interleaveIssuance(t, stage, func() {
					m.Generation++
					m.Roles = maps.Clone(m.Roles)
					m.Roles["viewer"] = []*basev0.WorkScopeV1{testkit.Scope("wiki.page", "read"), testkit.Scope("documents", "read"), testkit.Scope("directory.entry", "read")}
					if _, err := k.State.ApplyManifest(m); err != nil {
						t.Fatal(err)
					}
				}, issue)
				if err != nil {
					return
				}
				if _, err := k.Issuer.Check(context.Background(), out.Token, out.Context.Audience, ""); err == nil {
					t.Fatal("stale solution write was signed with current authorization")
				}
			})
		}
	}
}

func TestSolutionInstallerAndTeamRolesRemainDistinctSources(t *testing.T) {
	k := testkit.New(t)
	m := testkit.Proposals(2)
	m.Bindings = map[string]state.Binding{"documents": {ID: "documents", Audience: "documents", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("documents", "read", "write")}}}
	m.Roles[state.InstallerRole] = append(m.Roles[state.InstallerRole], testkit.Scope("documents", "write"))
	m.Roles["viewer"] = append(m.Roles["viewer"], testkit.Scope("documents", "read"))
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	inst, err := k.State.Install(context.Background(), "acme", "proposals", "viewer", "alex")
	if err != nil {
		t.Fatal(err)
	}
	check := func(who string, actions ...string) {
		t.Helper()
		got, err := k.State.PersonSolutionScopes(who, "proposals")
		if err != nil {
			t.Fatal(err)
		}
		for _, action := range []string{"read", "write"} {
			want := false
			for _, expected := range actions {
				want = want || action == expected
			}
			if state.Attenuates([]*basev0.WorkScopeV1{testkit.Scope("documents", action)}, got) != want {
				t.Fatalf("%s incorrectly holds %s: %v", who, action, got)
			}
		}
	}
	check("alex", "write")
	check("maya")
	check("zoe")
	if _, err := k.State.GrantToTeam(context.Background(), "acme", inst.ID, "finance"); err != nil {
		t.Fatal(err)
	}
	check("alex", "read", "write")
	check("maya", "read")
	check("remi")
	check("zoe")
}

func TestEverySolutionInPersonChainRemainsACeiling(t *testing.T) {
	for _, narrow := range []string{"wiki", "proposals"} {
		t.Run(narrow, func(t *testing.T) {
			k, a := solutionRoleKit(t, testkit.Scope("documents", "read", "write"))
			b := testkit.Proposals(2)
			b.Bindings = a.Bindings
			b.Roles["viewer"] = append(b.Roles["viewer"], testkit.Scope("documents", "read", "write"), testkit.Scope("directory.entry", "read"))
			if narrow == "proposals" {
				b.Roles["viewer"][1] = testkit.Scope("documents", "read")
			}
			if _, err := k.State.ApplyManifest(b); err != nil {
				t.Fatal(err)
			}
			a.Generation++
			a.Roles = maps.Clone(a.Roles)
			a.Roles["viewer"] = []*basev0.WorkScopeV1{testkit.Scope("wiki.page", "read"), testkit.Scope("documents", "read", "write"), testkit.Scope("directory.entry", "read"), testkit.Scope("proposals.item", "read")}
			if narrow == "wiki" {
				a.Roles["viewer"][1] = testkit.Scope("documents", "read")
			}
			a.Bindings = maps.Clone(a.Bindings)
			a.Bindings["tools"] = state.Binding{ID: "tools", Audience: "proposals", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "read")}}
			if _, err := k.State.ApplyManifest(a); err != nil {
				t.Fatal(err)
			}
			inst, err := k.State.Install(context.Background(), "acme", "proposals", "viewer", "alex")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := k.State.GrantToTeam(context.Background(), "acme", inst.ID, "finance"); err != nil {
				t.Fatal(err)
			}
			root, err := k.Issuer.Issue(person(t, k, "fixture-maya"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "wiki"})
			if err != nil {
				t.Fatal(err)
			}
			hop := func(parent *authorityv1.IssueResponse, actor, binding, target, kind, action string) (*authorityv1.IssueResponse, error) {
				return k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, actor)}, OperationBindingId: binding, Audience: target, Scopes: scopes(testkit.Scope(kind, action))})
			}
			tools, err := hop(root, "wiki", "tools", "proposals", "proposals.item", "read")
			if err != nil {
				t.Fatal(err)
			}
			later, err := hop(tools, "proposals", "directory", "org-directory", "directory.entry", "read")
			if err != nil {
				t.Fatal(err)
			}
			for _, parent := range []*authorityv1.IssueResponse{tools, later} {
				actor := parent.Context.Audience
				read, err := hop(parent, actor, "documents", "documents", "documents", "read")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := k.Issuer.Check(context.Background(), read.Token, "documents", ""); err != nil {
					t.Fatal(err)
				}
				if _, err := hop(parent, actor, "documents", "documents", "documents", "write"); !errors.Is(err, issuer.ErrRefused) {
					t.Fatalf("%s recovered write beyond %s: %v", actor, narrow, err)
				}
			}
		})
	}
}
