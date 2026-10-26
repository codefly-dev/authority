package testkit

import (
	"context"
	"gateway/pkg/business/state"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"testing"
)

// SolutionToolMethod is the target operation the module calls as a tool.
const SolutionToolMethod = "/tools.Solution/Read"

// SolutionToolBinding is the prepared key the CLI derives for that operation
// from the `runnable-bindings` group (MODULE__OPERATION). A module issues each
// runnable tool call through its operation's own key, never one shared binding.
const SolutionToolBinding = "PROPOSALS__TOOLS_SOLUTION_READ"

// SolutionTools composes a module binding to a solution entitled only to finance.
// The ordinary fixture's wiki is also granted to engineering, so it cannot
// distinguish Maya from Remi for the tool-call entitlement test.
//
// The module's binding is composed the way the CLI delivers it: one binding per
// prepared operation, id the key, audience the target, invoke scopes the
// operation's.
func SolutionTools(t *testing.T, k *Kit) {
	t.Helper()
	read := []*basev0.WorkScopeV1{Scope("proposals.item", "read")}
	target := Proposals(1)
	target.Methods = map[string]state.MethodPolicy{SolutionToolMethod: {Requires: read}}
	actor := state.Manifest{Name: "robin", Principal: "robin", Kind: "module", Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{Scope("robin.conversations", "read")},
		Bindings:      map[string]state.Binding{SolutionToolBinding: {ID: SolutionToolBinding, Audience: "proposals", InvokeScopes: read}},
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
