package issuer_test

import (
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	base "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func TestMalformedAskDoesNotGainAuthority(t *testing.T) {
	for _, scope := range []*authorityv1.WorkScopeV1{nil, {}, {ResourceKind: "modelservice.profiles"}, {Actions: []string{"invoke"}}} {
		k := testkit.New(t)
		out, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model", Scopes: []*authorityv1.WorkScopeV1{scope}})
		if err != nil {
			continue
		}
		for _, action := range []string{"read", "invoke"} {
			if _, err = k.Issuer.ListResources(t.Context(), out.Token, "model", "modelservice.profiles", action); err == nil {
				t.Fatalf("malformed root gained %s", action)
			}
		}
		root, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "documents"})
		if err != nil {
			t.Fatal(err)
		}
		child, err := k.Issuer.Issue(t.Context(), &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "documents")}, Audience: "model", OperationBindingId: "model", Scopes: []*authorityv1.WorkScopeV1{scope}})
		if err == nil {
			t.Fatalf("malformed child accepted: %v", child)
		}
	}
}

func TestParentLimitsPreserveActionSpecificResources(t *testing.T) {
	k := testkit.New(t)
	model := testkit.Model(2)
	model.Bindings = map[string]state.Binding{
		"documents": testkit.OrgDirectory(1).Bindings["documents"],
	}
	if _, err := k.State.ApplyManifest(model); err != nil {
		t.Fatal(err)
	}
	parent, err := k.Issuer.Issue(person(t, k, "fixture-remi"), &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: "model",
		Scopes: scopes(
			&base.WorkScopeV1{ResourceKind: "modelservice.profiles", Actions: []string{"read"}, ResourceIds: []string{"a"}},
			&base.WorkScopeV1{ResourceKind: "modelservice.profiles", Actions: []string{"invoke"}, ResourceIds: []string{"b"}},
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		parent, err = hopFrom(t, k, parent, "model", "documents", "documents")
		if err != nil {
			t.Fatal(err)
		}
		parent, err = hopFrom(t, k, parent, "documents", "model", "model")
		if err != nil {
			t.Fatal(err)
		}
		for action, id := range map[string]string{"read": "a", "invoke": "b"} {
			grants, err := k.Issuer.ListResources(t.Context(), parent.Token, "model", "modelservice.profiles", action)
			if err != nil || len(grants) != 1 || grants[0].ID != id {
				t.Fatalf("%s must grant only %s: grants=%v err=%v", action, id, grants, err)
			}
		}
	}
}
