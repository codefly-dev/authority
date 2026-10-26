package state_test

import (
	"errors"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"

	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

// ownedWiki consumes documents.collection read only on what an installation owns.
func ownedWiki(generation uint64) state.Manifest {
	m := testkit.Wiki(generation)
	m.Bindings = map[string]state.Binding{"documents": {ID: "documents", Audience: "documents", InvokeScopes: []*basev0.WorkScopeV1{testkit.Scope("documents.collection", "read")}}}
	m.OwnedRoles = map[string][]*basev0.WorkScopeV1{"viewer": {testkit.Scope("documents.collection", "read")}}
	return m
}

func TestAnInstallationOwnedScopeIsDeclaredWithoutIDsOnADeclaredRole(t *testing.T) {
	k := testkit.New(t)
	withIDs := ownedWiki(2)
	withIDs.OwnedRoles["viewer"][0].ResourceIds = []string{"finance"}
	undeclared := ownedWiki(2)
	undeclared.OwnedRoles["auditor"] = undeclared.OwnedRoles["viewer"]
	beyond := ownedWiki(2)
	beyond.OwnedRoles["viewer"] = []*basev0.WorkScopeV1{testkit.Scope("documents.collection", "admin")}
	module := testkit.Documents(2)
	module.OwnedRoles = map[string][]*basev0.WorkScopeV1{"viewer": {testkit.Scope("documents", "read")}}
	for name, m := range map[string]state.Manifest{"ids": withIDs, "undeclared role": undeclared, "beyond the binding": beyond, "a module": module} {
		if _, err := k.State.ApplyManifest(m); !errors.Is(err, state.ErrForbidden) {
			t.Errorf("%s: want ErrForbidden, got %v", name, err)
		}
	}
	onlyOwned := ownedWiki(2)
	onlyOwned.Roles["viewer"] = nil
	if _, err := k.State.ApplyManifest(onlyOwned); err != nil {
		t.Fatalf("a role granting only installation-owned scopes is a role: %v", err)
	}
}
