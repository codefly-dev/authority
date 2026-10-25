package issuer_test

import (
	"errors"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func hopFrom(t *testing.T, k *testkit.Kit, parent *authorityv1.IssueResponse, actor, target, binding string, ask ...*base.WorkScopeV1) (*authorityv1.IssueResponse, error) {
	t.Helper()
	return k.Issuer.Issue(t.Context(), &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token},
		Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, actor)},
		Audience: target, OperationBindingId: binding, Scopes: scopes(ask...),
	})
}

func effectiveScopes(wc *authorityv1.WorkContextV1) []*authorityv1.WorkScopeV1 {
	scopes := wc.GetAuthorityScopes()
	if chain := wc.GetActorChain(); len(chain) > 0 {
		scopes = chain[len(chain)-1].GetGrantedScopes()
	}
	var effective []*authorityv1.WorkScopeV1
	for _, scope := range scopes {
		if len(scope.GetActions()) > 0 {
			effective = append(effective, scope)
		}
	}
	return effective
}

func TestParentLimitsSurviveIntermediateAudiences(t *testing.T) {
	k := testkit.New(t)
	model := testkit.Model(2)
	model.Bindings = map[string]state.Binding{
		"documents": testkit.OrgDirectory(1).Bindings["documents"],
		"self":      {ID: "self", Audience: "model", InvokeScopes: testkit.Documents(1).Bindings["model"].InvokeScopes},
	}
	if _, err := k.State.ApplyManifest(model); err != nil {
		t.Fatal(err)
	}
	root, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model",
		Scopes: scopes(&base.WorkScopeV1{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"a"}}),
	})
	if err != nil {
		t.Fatal(err)
	}
	parent := root
	for range 3 {
		intermediate, err := hopFrom(t, k, parent, "model", "documents", "documents")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.Issuer.ListResources(t.Context(), intermediate.Token, "documents", "modelservice.profiles", "read"); !errors.Is(err, issuer.ErrRefused) {
			t.Fatalf("a carried cap authorizes another audience: %v", err)
		}
		returned, err := hopFrom(t, k, intermediate, "documents", "model", "model")
		if err != nil {
			t.Fatal(err)
		}
		got := effectiveScopes(returned.Context)
		if len(got) != 1 || len(got[0].Actions) != 1 || got[0].Actions[0] != "read" || len(got[0].ResourceIds) != 1 || got[0].ResourceIds[0] != "a" {
			t.Fatalf("parent narrowing recovered: %v", got)
		}
		for _, ask := range []*base.WorkScopeV1{
			testkit.Scope("modelservice.profiles", "invoke"),
			{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"b"}},
		} {
			if _, err := hopFrom(t, k, intermediate, "documents", "model", "model", ask); !errors.Is(err, issuer.ErrRefused) {
				t.Fatalf("widened parent: %v", err)
			}
		}
		parent = returned
	}
}

func TestExplicitlyDroppedKindNeverReturns(t *testing.T) {
	for _, where := range []string{"root", "child"} {
		t.Run(where, func(t *testing.T) {
			k := testkit.New(t)
			// Two kinds the same owner holds at the target. The named binding
			// reaches both; an explicit ask deliberately retains only one.
			model := testkit.Model(2)
			model.ResourceKinds = append(model.ResourceKinds, testkit.Scope("documents", "read", "write"))
			model.Bindings = map[string]state.Binding{"self": {ID: "self", Audience: "model", InvokeScopes: model.ResourceKinds}}
			if _, err := k.State.ApplyManifest(model); err != nil {
				t.Fatal(err)
			}
			req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model"}
			if where == "root" {
				req.Scopes = scopes(testkit.Scope("modelservice.profiles", "read"))
			}
			parent, err := k.Issuer.Issue(person(t, k, "fixture-remi"), req)
			if err != nil {
				t.Fatal(err)
			}
			if where == "child" {
				parent, err = hopFrom(t, k, parent, "model", "model", "self", testkit.Scope("modelservice.profiles", "read"))
				if err != nil {
					t.Fatal(err)
				}
			}
			for range 4 {
				parent, err = hopFrom(t, k, parent, "model", "model", "self")
				if err != nil {
					t.Fatal(err)
				}
				got := effectiveScopes(parent.Context)
				if len(got) != 1 || got[0].ResourceKind != "modelservice.profiles" {
					t.Fatalf("dropped kind restored: %v", got)
				}
				if _, err := hopFrom(t, k, parent, "model", "model", "self", testkit.Scope("documents", "read")); !errors.Is(err, issuer.ErrRefused) {
					t.Fatalf("dropped kind requested: %v", err)
				}
			}
		})
	}
}

func TestDisjointTargetScopeStaysDeniedAfterLaterHops(t *testing.T) {
	for _, reason := range []string{"actions", "resources"} {
		t.Run(reason, func(t *testing.T) {
			k := testkit.New(t)
			model := testkit.Model(2)
			model.ResourceKinds = append(model.ResourceKinds, testkit.Scope("documents", "read", "write"))
			disjoint := &base.WorkScopeV1{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"b"}}
			if reason == "actions" {
				disjoint.Actions, disjoint.ResourceIds = []string{"invoke"}, nil
			}
			model.Bindings = map[string]state.Binding{
				"self":     {ID: "self", Audience: "model", InvokeScopes: model.ResourceKinds},
				"disjoint": {ID: "disjoint", Audience: "model", InvokeScopes: []*base.WorkScopeV1{disjoint, testkit.Scope("documents", "read")}},
			}
			model.Methods = map[string]state.MethodPolicy{
				"/model.Service/ReadDocument": {Requires: []*base.WorkScopeV1{testkit.Scope("documents", "read")}},
				"/model.Service/ReadProfile":  {Requires: []*base.WorkScopeV1{testkit.Scope("modelservice.profiles", "read")}},
			}
			if _, err := k.State.ApplyManifest(model); err != nil {
				t.Fatal(err)
			}
			parent, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
				As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model",
				Scopes: scopes(&base.WorkScopeV1{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"a"}}, testkit.Scope("documents", "read")),
			})
			if err != nil {
				t.Fatal(err)
			}
			parent, err = hopFrom(t, k, parent, "model", "model", "disjoint")
			if err != nil {
				t.Fatal(err)
			}
			for range 4 {
				parent, err = hopFrom(t, k, parent, "model", "model", "self")
				if err != nil {
					t.Fatal(err)
				}
				got := effectiveScopes(parent.Context)
				if len(got) != 1 || got[0].ResourceKind != "documents" {
					t.Fatalf("disjoint kind recovered: %v", got)
				}
				if _, err := k.Issuer.Check(t.Context(), parent.Token, "model", "/model.Service/ReadDocument"); err != nil {
					t.Fatal(err)
				}
				if _, err := k.Issuer.Check(t.Context(), parent.Token, "model", "/model.Service/ReadProfile"); !errors.Is(err, state.ErrForbidden) {
					t.Fatalf("denied kind admitted by policy: %v", err)
				}
				if _, err := k.Issuer.ListResources(t.Context(), parent.Token, "model", "modelservice.profiles", "read"); !errors.Is(err, issuer.ErrRefused) {
					t.Fatalf("denied kind discovered: %v", err)
				}
			}
		})
	}
}
