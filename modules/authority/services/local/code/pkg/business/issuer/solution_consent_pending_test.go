//go:build pending

package issuer_test

import (
	"context"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"strings"
	"testing"
)

// Row 11 stays pending until target-solution consent is represented by the
// authority. A source solution declaring another solution's kind is not consent.
// A generic installation-seal failure on the second hop is not this proof either.
func TestInstallationToolRequiresTargetSolutionConsent(t *testing.T) {
	k := testkit.New(t)
	testkit.SolutionTools(t, k)
	a := testkit.Wiki(2)
	a.Bindings = map[string]state.Binding{
		"assistant": {ID: "assistant", Audience: "robin", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("robin.conversations", "read")}},
		"tools":     {ID: "tools", Audience: "proposals", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("proposals.item", "read")}},
	}
	a.Roles["viewer"] = append(a.Roles["viewer"], testkit.Scope("robin.conversations", "read"), testkit.Scope("proposals.item", "read"))
	if _, err := k.State.ApplyManifest(a); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	credential := &authorityv1.WorkloadCredential{Credential: k.Credential(t, "wiki")}
	installation := &authorityv1.IssueRequest_Installation{Installation: &authorityv1.InstallationRef{InstallationId: state.InstallationID("acme", "wiki")}}
	t.Run("direct", func(t *testing.T) {
		_, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: installation, Actor: credential, Audience: "proposals", Scopes: scopes(testkit.Scope("proposals.item", "read"))})
		if err == nil {
			t.Fatal("pending target consent: source role alone issued authority for another solution")
		}
		if !strings.Contains(err.Error(), "consent") {
			t.Fatalf("target consent was not the refusal: %v", err)
		}
	})
	t.Run("through module", func(t *testing.T) {
		root, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: installation, Actor: credential, Audience: "wiki"})
		if err != nil {
			t.Fatal(err)
		}
		middle, err := k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: root.Token}, Actor: credential, Audience: "robin", OperationBindingId: "assistant", Scopes: scopes(testkit.Scope("robin.conversations", "read"))})
		if err != nil {
			t.Fatalf("source-to-module precondition must work before testing target consent: %v", err)
		}
		_, err = k.Issuer.Issue(ctx, &authorityv1.IssueRequest{As: &authorityv1.IssueRequest_ParentToken{ParentToken: middle.Token}, Actor: &authorityv1.WorkloadCredential{Credential: k.Credential(t, "robin")}, Audience: "proposals", OperationBindingId: testkit.SolutionToolBinding, Scopes: scopes(testkit.Scope("proposals.item", "read"))})
		if err == nil || !strings.Contains(err.Error(), "consent") {
			t.Fatalf("pending target consent: require a target-consent refusal, not generic seal failure: %v", err)
		}
	})
}
