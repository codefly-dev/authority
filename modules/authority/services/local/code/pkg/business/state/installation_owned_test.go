package state_test

import (
	"context"
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

func TestAnInstallationOwnsOnlyWhatWasAttachedSinceItWasInstalled(t *testing.T) {
	k := testkit.New(t)
	if _, err := k.State.ApplyManifest(ownedWiki(2)); err != nil {
		t.Fatal(err)
	}
	id := state.InstallationID("acme", "wiki")
	held := func() []*basev0.WorkScopeV1 {
		t.Helper()
		scopes, err := k.State.PersonSolutionScopes("maya", "wiki")
		if err != nil {
			t.Fatal(err)
		}
		return state.Intersect(scopes, []*basev0.WorkScopeV1{testkit.Scope("documents.collection", "read")})
	}
	if got := held(); len(got) != 0 {
		t.Fatalf("an installation owning nothing grants nothing, never the whole kind: %v", got)
	}
	if _, err := k.State.AttachResource("acme", nil, "documents.collection", "c1"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("no installation: %v", err)
	}
	if _, err := k.State.AttachResource("acme", []string{id, state.InstallationID("acme", "proposals")}, "documents.collection", "c1"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("two installations: %v", err)
	}
	if _, err := k.State.AttachResource("globex", []string{id}, "documents.collection", "c1"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("another organization: %v", err)
	}
	before, _ := k.State.Installation(id)
	for range 2 {
		if _, err := k.State.AttachResource("acme", []string{id}, "documents.collection", "c1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := held(); len(got) != 1 || len(got[0].GetResourceIds()) != 1 || got[0].GetResourceIds()[0] != "c1" {
		t.Fatalf("held %v, want read on c1 alone", got)
	}
	if len(before.Owned) != 0 {
		t.Fatalf("a copy read before the attachment changed under its reader: %v", before.Owned)
	}
	if err := k.State.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.Install(context.Background(), "acme", "wiki", "viewer", "alex"); err != nil {
		t.Fatal(err)
	}
	if _, err := k.State.GrantToTeam(context.Background(), "acme", id, "finance"); err != nil {
		t.Fatal(err)
	}
	if got := held(); len(got) != 0 {
		t.Fatalf("a reinstalled installation inherited its predecessor's resources: %v", got)
	}
}
