package composition

import (
	"slices"
	"testing"

	"gateway/pkg/business/state"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/solutionhost"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Core's manifest writes a binding's operations as operation → "<kind>:<action>"
// entries; the state reads invoke and headless scopes from them.
func TestCoreBindingOperationsAreReadAsScopesPerOperation(t *testing.T) {
	m := FromCore(&solutionhost.ModuleManifest{Alias: "robin", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "robin", Bindings: []solutionhost.AuthorityBinding{{
			ID: "model", Audience: "model",
			Operations: map[string][]string{
				"invoke":   {"modelservice.profiles:invoke", "modelservice.profiles:read"},
				"lookup":   {"modelservice.profiles:read"},
				"headless": {"modelservice.profiles:read"},
			},
		}}}})
	b, ok := m.Bindings["model"]
	if !ok || b.Audience != "model" {
		t.Fatalf("binding: %+v", m.Bindings)
	}
	if len(b.InvokeScopes) != 1 || b.InvokeScopes[0].GetResourceKind() != "modelservice.profiles" || len(b.InvokeScopes[0].GetActions()) != 2 {
		t.Fatalf("invoke scopes: %v", b.InvokeScopes)
	}
	if len(b.HeadlessScopes) != 1 || b.HeadlessScopes[0].GetActions()[0] != "read" {
		t.Fatalf("headless scopes: %v", b.HeadlessScopes)
	}
}

// A module's own kinds come from core's manifest as names; the authority's
// document gives each the actions the contract declares, so a person who holds
// everything there is granted those actions rather than an action nobody can
// enumerate.
func TestScopeCeilingsGiveTheModulesKindsTheirActions(t *testing.T) {
	m := FromCore(&solutionhost.ModuleManifest{Alias: "runtime", Kind: solutionhost.KindModule, Generation: 1,
		Authority: &solutionhost.Authority{Principal: "runtime", ResourceKinds: []string{"runtime.tasks", "runtime.queues"}}})
	got, err := ceiled(m, []*basev0.WorkScopeV1{{ResourceKind: "runtime.tasks", Actions: []string{"start", "execute"}}})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string][]string{}
	for _, kind := range got.ResourceKinds {
		actions[kind.GetResourceKind()] = kind.GetActions()
	}
	if len(actions["runtime.tasks"]) != 2 || slices.Contains(actions["runtime.tasks"], state.AnyAction) {
		t.Fatalf("runtime.tasks serves %v", actions["runtime.tasks"])
	}
	// A kind the document does not ceil keeps what core's manifest gave it.
	if !slices.Equal(actions["runtime.queues"], []string{state.AnyAction}) {
		t.Fatalf("runtime.queues serves %v", actions["runtime.queues"])
	}
	// The document narrows what core composes and never adds a kind.
	for name, ceilings := range map[string][]*basev0.WorkScopeV1{
		"a kind core does not declare": {{ResourceKind: "records.records", Actions: []string{"write"}}},
		"a kind with no action":        {{ResourceKind: "runtime.tasks"}},
	} {
		if _, err := ceiled(m, ceilings); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
}
