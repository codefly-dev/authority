package offers_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/offers"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
)

func TestProjectionPreservesMemberReadAndAttachedResources(t *testing.T) {
	scope := &basev0.WorkScopeV1{ResourceKind: "records.item", Actions: []string{"read"}}
	offer := authority.ReviewedOffer{
		Module:       domain.Module{Name: "solution", Roles: map[string][]*basev0.WorkScopeV1{"viewer": nil}, OwnedRoles: map[string][]*basev0.WorkScopeV1{"viewer": {scope}}},
		Installation: domain.Installation{ID: "installation", Owned: map[string][]string{"records.item": {"record-a"}}},
		Modules: []domain.Module{{Name: "records", Methods: map[string]domain.MethodPolicy{
			"/records.Items/Read":  {Requires: []*basev0.WorkScopeV1{scope}},
			"/records.Items/Write": {Requires: []*basev0.WorkScopeV1{{ResourceKind: "records.item", Actions: []string{"write"}}}},
		}}},
	}
	got, err := offers.Project(offer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Approval != nil || got.ToolsComposed || got.Installation.ID != "installation" {
		t.Fatalf("member projection: %+v", got)
	}
	role := got.Roles[0]
	if role.Name != "viewer" || len(role.Scopes) != 1 || !role.Scopes[0].AttachedOnly || len(role.Scopes[0].ResourceIDs) != 1 || role.Scopes[0].ResourceIDs[0] != "record-a" {
		t.Fatalf("attached scope: %+v", role)
	}
	if len(role.Capabilities) != 1 || role.Capabilities[0].Operation != "/records.Items/Read" {
		t.Fatalf("role reached an uncovered operation: %+v", role.Capabilities)
	}
	role.Scopes[0].ResourceIDs[0] = "changed"
	if offer.Installation.Owned["records.item"][0] != "record-a" {
		t.Fatal("projection aliases attached resources")
	}
}

func TestInvalidExposedToolFailsProjection(t *testing.T) {
	sc := &basev0.WorkScopeV1{ResourceKind: "records.item", Actions: []string{"read"}}
	offer := authority.ReviewedOffer{Module: domain.Module{Name: "solution", Roles: map[string][]*basev0.WorkScopeV1{"viewer": {sc}}}, Modules: []domain.Module{{Name: "records", Methods: map[string]domain.MethodPolicy{"/records.Items/Read": {Requires: []*basev0.WorkScopeV1{sc}}}}}}
	// It names an exposed operation but lacks the prepared contract and digest;
	// a host must show the refusal, never silently omit the broken tool.
	bindings := map[string]*runnablev0.PreparedBinding{"BROKEN": {
		Operation: &runnablev0.PreparedOperation{Module: "records", Spelling: "/records.Items/Read", Endpoint: "connect"},
		Policy:    &runnablev0.Operation{Tool: &runnablev0.ToolExposure{Name: "read_items"}, InvokeScopes: []*basev0.WorkScopeV1{sc}},
		Call:      &runnablev0.PreparedCall{Route: &runnablev0.PreparedCall_Connect{Connect: &runnablev0.ConnectProcedure{Procedure: "/records.Items/Read"}}},
	}}
	_, err := offers.Project(offer, bindings)
	code, ok := domain.CodeOf(err)
	if !ok || code != domain.Precondition {
		t.Fatalf("invalid tool refusal: %v", err)
	}
}
