package issuer_test

import (
	"context"
	"errors"
	"testing"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
	authorityv1 "gateway/pkg/gen/host/authority/v1"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func TestRestrictedCapabilityIsRefusedForKindWideMethodAndAdvisedWithoutWidening(t *testing.T) {
	k := testkit.New(t)
	m := testkit.Documents(2)
	method := "/documents.Service/ListCollections"
	m.Methods = map[string]state.MethodPolicy{method: {Requires: []*basev0.WorkScopeV1{{ResourceKind: "documents.collection", Actions: []string{"read"}}}}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	token := issued(t, k, "fixture-remi", []*authorityv1.WorkScopeV1{{ResourceKind: "documents.collection", Actions: []string{"read"}, ResourceIds: []string{"one"}}})
	ctx := context.Background()
	if _, err := k.Issuer.Check(ctx, token, "documents", method); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("resource-limited capability admitted kind-wide: %v", err)
	}
	advice, err := k.Issuer.Advise(ctx, token, "documents", method)
	if err != nil {
		t.Fatal(err)
	}
	if advice.GetRefusal() == "" {
		t.Fatal("warn mode lost the method refusal")
	}
	if len(advice.GetContext().GetAuthorityScopes()) != 1 || len(advice.GetContext().GetAuthorityScopes()[0].GetResourceIds()) != 1 || advice.GetContext().GetAuthorityScopes()[0].GetResourceIds()[0] != "one" {
		t.Fatalf("warn mode widened the signed capability: %v", advice.GetContext())
	}
	if _, err := k.Issuer.Check(ctx, token, "documents", ""); err != nil {
		t.Fatalf("identity verification alone must retain the restricted capability: %v", err)
	}
	whole := issued(t, k, "fixture-remi", nil)
	if _, err := k.Issuer.Check(ctx, whole, "documents", method); err != nil {
		t.Fatalf("whole-kind read refused: %v", err)
	}
}
