package testkit

import (
	"context"
	"gateway/pkg/business/state"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"testing"
)

// SolutionTools composes a module binding to a solution entitled only to finance.
// The ordinary fixture's wiki is also granted to engineering, so it cannot
// distinguish Maya from Remi for the tool-call entitlement test.
func SolutionTools(t *testing.T, k *Kit) {
	t.Helper()
	target := Proposals(1)
	target.Methods = map[string]state.MethodPolicy{
		"/tools.Solution/Read": {Requires: []*basev0.WorkScopeV1{Scope("proposals.item", "read")}},
	}
	actor := state.Manifest{Name: "robin", Principal: "robin", Kind: "module", Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("robin.conversations", "read")},
		Bindings:      map[string]state.Binding{"tools": {ID: "tools", Audience: "proposals", InvokeScopes: []*basev0.WorkScopeV1{Scope("proposals.item", "read")}}},
	}
	for _, m := range []state.Manifest{target, actor} {
		if _, err := k.State.ApplyManifest(m); err != nil {
			t.Fatal(err)
		}
	}
	inst, err := k.State.Install(context.Background(), "acme", "proposals", "viewer", "alex")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.State.GrantRole(domain.RoleGrant{InstallationID: inst.ID, Role: "viewer", TeamID: "finance"}); err != nil {
		t.Fatal(err)
	}
}
