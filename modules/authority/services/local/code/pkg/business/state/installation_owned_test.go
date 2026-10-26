package state_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	testkit.SolutionTools(t, k)
	id, other := state.InstallationID("acme", "wiki"), state.InstallationID("acme", "proposals")
	revision := func() uint64 {
		t.Helper()
		r, err := k.State.AuthorizationRevision(context.Background(), "acme")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
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
	refusals := map[string]struct {
		tenant     string
		revision   uint64
		candidates []string
		id         string
	}{
		"no installation":        {"acme", revision(), nil, "c1"},
		"two installations":      {"acme", revision(), []string{id, other}, "c1"},
		"another organization":   {"globex", revision(), []string{id}, "c1"},
		"a superseded revision":  {"acme", revision() - 1, []string{id}, "c1"},
		"an id past its length":  {"acme", revision(), []string{id}, strings.Repeat("x", state.MaxResourceIDBytes+1)},
		"an empty id":            {"acme", revision(), []string{id}, ""},
		"surrounding whitespace": {"acme", revision(), []string{id}, " c1"},
		"a newline":              {"acme", revision(), []string{id}, "c\n1"},
		"a NUL":                  {"acme", revision(), []string{id}, "c\x001"},
		"a tab":                  {"acme", revision(), []string{id}, "c\t1"},
		"the wildcard":           {"acme", revision(), []string{id}, "*"},
		"a wildcard inside":      {"acme", revision(), []string{id}, "c*"},
	}
	for name, r := range refusals {
		if _, err := k.State.AttachResource(r.tenant, r.revision, r.candidates, "documents.collection", r.id); !errors.Is(err, state.ErrForbidden) {
			t.Errorf("%s: want ErrForbidden, got %v", name, err)
		}
	}
	before, _ := k.State.Installation(id)
	for range 2 {
		if _, err := k.State.AttachResource("acme", revision(), []string{id}, "documents.collection", "c1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := held(); len(got) != 1 || len(got[0].GetResourceIds()) != 1 || got[0].GetResourceIds()[0] != "c1" {
		t.Fatalf("held %v, want read on c1 alone", got)
	}
	if len(before.Owned) != 0 {
		t.Fatalf("a copy read before the attachment changed under its reader: %v", before.Owned)
	}
	if _, err := k.State.AttachResource("acme", revision(), []string{other}, "documents.collection", "c1"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("a resource has one owner in a tenant: %v", err)
	}
	for n := 1; n < state.MaxOwnedPerKind; n++ {
		if _, err := k.State.AttachResource("acme", revision(), []string{id}, "documents.collection", fmt.Sprintf("c%d", n+1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := k.State.AttachResource("acme", revision(), []string{id}, "documents.collection", "one-too-many"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("past the bound a capability carries: %v", err)
	}
	// The bound counts what is owned now: a detached id frees its place, and
	// detaching narrows, so a revision from before it is superseded.
	beforeDetach := revision()
	if from, err := k.State.DetachResource("acme", "documents.collection", "c2"); err != nil || from != id {
		t.Fatalf("detach: %q %v", from, err)
	}
	if _, err := k.State.AttachResource("acme", beforeDetach, []string{id}, "documents.collection", "one-too-many"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("a capability from before a detachment is superseded: %v", err)
	}
	if _, err := k.State.AttachResource("acme", revision(), []string{id}, "documents.collection", "one-too-many"); err != nil {
		t.Fatalf("a detached id frees its place: %v", err)
	}
	if from, err := k.State.DetachResource("acme", "documents.collection", "nobody-owns-this"); err != nil || from != "" {
		t.Fatalf("detaching an unowned id: %q %v", from, err)
	}
	// A capability minted before an uninstall never attaches into the
	// reinstalled installation, though its id is the same.
	minted := revision()
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
	if _, err := k.State.AttachResource("acme", minted, []string{id}, "documents.collection", "late"); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("a pre-uninstall capability attached into the reinstalled installation: %v", err)
	}
}
