package state_test

import (
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev1 "github.com/codefly-dev/core/generated/go/codefly/base/v1"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// What a module's methods require is what it serves: a person whose role covers
// that kind and action is granted it at the module, even when none of the
// manifest's other declarations named the kind.
func TestAModuleServesWhatItsMethodsRequire(t *testing.T) {
	k := testkit.New(t)
	define := []*basev1.WorkScopeV1{{ResourceKind: "ledger.accounts", Actions: []string{"define"}}}
	m := state.Manifest{Name: "ledger", Principal: "ledger", Kind: "module", Generation: 1, Bindings: map[string]state.Binding{},
		Page: true, InstallationRole: "none",
		Roles: map[string][]*basev1.WorkScopeV1{state.AdminRole: define, state.UserRole: define},
		Methods: map[string]state.MethodPolicy{
			"/ledger.v1.Ledger/DefineAccount": {Requires: define},
		}}
	if _, err := k.State.ApplyManifest(m); err != nil {
		t.Fatal(err)
	}
	if err := k.State.GrantRole(domain.RoleGrant{InstallationID: state.InstallationID("acme", "ledger"), Role: state.UserRole, PersonID: "dev"}); err != nil {
		t.Fatal(err)
	}
	held, err := k.PersonScopes(t, "dev", "ledger")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(held, func(s *basev1.WorkScopeV1) bool {
		return s.GetResourceKind() == "ledger.accounts" && slices.Contains(s.GetActions(), "define")
	}) {
		t.Fatalf("a kind the module's methods require is not granted: %v", held)
	}
}
