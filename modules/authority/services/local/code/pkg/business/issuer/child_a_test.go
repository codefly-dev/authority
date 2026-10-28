package issuer_test

import (
	"context"
	"errors"
	"testing"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The explicit grant covers both targets, even though its first token is
// projected only at documents. A binding is not an implicit transitive grant.
func declareDelegationChain(t *testing.T, k *testkit.Kit) {
	t.Helper()
	directory := testkit.OrgDirectory(2)
	directory.Bindings["model"] = testkit.Documents(1).Bindings["model"]
	if _, err := k.State.ApplyManifest(directory); err != nil {
		t.Fatal(err)
	}
}

func TestChildUsesOnlyCurrentTargetBinding(t *testing.T) {
	k := testkit.New(t)
	p, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "org-directory"})
	if err != nil {
		t.Fatal(err)
	}
	req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: p.Token},
		Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")},
		Audience: "documents", OperationBindingId: "documents"}
	out, err := k.Issuer.Issue(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(effectiveScopes(out.Context)) != 1 || actions(out.Context, "documents") != "read,write" {
		t.Fatalf("child retained unrelated parent grants: %v", effectiveScopes(out.Context))
	}
	req.Scopes = scopes(testkit.Scope("directory.entry", "read"))
	if _, err := k.Issuer.Issue(context.Background(), req); !errors.Is(err, issuer.ErrRefused) {
		t.Fatalf("parent scope outside target binding was admitted: %v", err)
	}
}

func TestChildRetainsExplicitDelegationAcrossTargetProjection(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent target", true: "restricted target"}[restricted], func(t *testing.T) {
			k := testkit.New(t)
			declareDelegationChain(t, k)
			model := testkit.Model(2)
			model.Bindings = map[string]state.Binding{"self": {ID: "self", Audience: "model", InvokeScopes: testkit.Documents(1).Bindings["model"].InvokeScopes}}
			if _, err := k.State.ApplyManifest(model); err != nil {
				t.Fatal(err)
			}
			grant := []*base.WorkScopeV1{testkit.Scope("documents", "read")}
			if restricted {
				grant = append(grant, &base.WorkScopeV1{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"a"}})
			}
			d, err := k.Issuer.Delegate(person(t, k, "fixture-remi"), "org-directory", grant, "bounded chain", 0)
			if err != nil {
				t.Fatal(err)
			}
			first, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
				As:       &authorityv1.IssueRequest_Delegation{Delegation: &authorityv1.DelegationRef{DelegationId: d.ID}},
				Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "org-directory")},
				Audience: "documents", OperationBindingId: "documents"})
			if err != nil {
				t.Fatal(err)
			}
			req := &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: first.Token},
				Actor:    &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")},
				Audience: "model", OperationBindingId: "model"}
			out, err := k.Issuer.Issue(context.Background(), req)
			if !restricted {
				if !errors.Is(err, issuer.ErrRefused) {
					t.Fatalf("missing delegated target admitted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := effectiveScopes(out.Context)
			if len(got) != 1 || actions(out.Context, "modelservice.profiles") != "read" ||
				len(got[0].ResourceIds) != 1 || got[0].ResourceIds[0] != "a" {
				t.Fatalf("delegation restriction lost: %v", effectiveScopes(out.Context))
			}
			if _, err := k.Issuer.Check(context.Background(), out.Token, "model", ""); err != nil {
				t.Fatal(err)
			}
			for _, ask := range []*base.WorkScopeV1{
				testkit.Scope("modelservice.profiles", "invoke"), testkit.Scope("modelservice.profiles", "read"),
				{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"b"}},
			} {
				req.Scopes = scopes(ask)
				if _, err := k.Issuer.Issue(context.Background(), req); !errors.Is(err, issuer.ErrRefused) {
					t.Fatalf("widened delegation accepted for %v: %v", ask, err)
				}
			}
			// Replay another actor at the same target: the stored grant still
			// constrains it, not merely the first downstream exchange.
			req.As = &authorityv1.IssueRequest_ParentToken{ParentToken: out.Token}
			req.Actor = &authorityv1.WorkloadCredential{Credential: k.Credential(t, "model")}
			req.OperationBindingId = "self"
			req.Scopes = nil
			later, err := k.Issuer.Issue(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(effectiveScopes(later.Context)) != 1 || actions(later.Context, "modelservice.profiles") != "read" ||
				len(effectiveScopes(later.Context)[0].ResourceIds) != 1 || effectiveScopes(later.Context)[0].ResourceIds[0] != "a" {
				t.Fatalf("later replay lost delegation restrictions: %v", effectiveScopes(later.Context))
			}
		})
	}
}

func TestBindingProjectionPersistsAndServiceOwnerNeverGainsNewAuthority(t *testing.T) {
	for _, serviceOwner := range []bool{false, true} {
		t.Run(map[bool]string{false: "person", true: "service"}[serviceOwner], func(t *testing.T) {
			k := testkit.New(t)
			model := testkit.Model(2)
			model.Bindings = map[string]state.Binding{"self": {ID: "self", Audience: "model", InvokeScopes: testkit.Documents(1).Bindings["model"].InvokeScopes}}
			if _, err := k.State.ApplyManifest(model); err != nil {
				t.Fatal(err)
			}
			var parent *authorityv1.IssueResponse
			var err error
			if serviceOwner {
				parent, err = k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
					As:             &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")}},
					OrganizationId: "acme", Audience: "model", OperationBindingId: "model", Scopes: scopes(testkit.Scope("modelservice.profiles", "read")),
				})
			} else {
				// A read-only binding constrains this kind on later hops too.
				docs := testkit.Documents(2)
				b := docs.Bindings["model"]
				b.InvokeScopes = []*base.WorkScopeV1{testkit.Scope("modelservice.profiles", "read")}
				b.HeadlessScopes = nil
				docs.Bindings["model"] = b
				if _, err := k.State.ApplyManifest(docs); err != nil {
					t.Fatal(err)
				}
				root, e := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
					As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents",
				})
				if e != nil {
					t.Fatal(e)
				}
				parent, err = k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
					As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")},
					Audience: "model", OperationBindingId: "model",
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
				As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "model")},
				Audience: "model", OperationBindingId: "self",
			})
			if err != nil {
				t.Fatal(err)
			}
			want := "read"
			if len(effectiveScopes(out.Context)) != 1 || actions(out.Context, "modelservice.profiles") != want {
				t.Fatalf("wrong owner-derived scope: %v", effectiveScopes(out.Context))
			}
		})
	}
}

func TestPersonIssueAskPersistsForTheSameKind(t *testing.T) {
	k := testkit.New(t)
	model := testkit.Model(2)
	model.Bindings = map[string]state.Binding{"self": {ID: "self", Audience: "model", InvokeScopes: testkit.Documents(1).Bindings["model"].InvokeScopes}}
	if _, err := k.State.ApplyManifest(model); err != nil {
		t.Fatal(err)
	}
	parent, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model", Scopes: scopes(testkit.Scope("modelservice.profiles", "read")),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := k.Issuer.Issue(context.Background(), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_ParentToken{ParentToken: parent.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "model")},
		Audience: "model", OperationBindingId: "self",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(effectiveScopes(out.Context)) != 1 || actions(out.Context, "modelservice.profiles") != "read" {
		t.Fatalf("a per-issue narrowing was recovered: %v", effectiveScopes(out.Context))
	}
}
