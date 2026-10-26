package hop_test

import (
	"context"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// ownedScope is {kind, [action], resource_owner_id: owner, resource_ids: ids}.
func ownedScope(t *testing.T, kind, action, owner string, ids ...string) *basev0.WorkScopeV1 {
	t.Helper()
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}, ResourceIds: ids, ResourceOwnerId: owner}
}

// The solution principal (conformance RunSolutionPrincipalTarget): A module fronted by the hop must
// never read an owner-selected scope as the whole kind: the stamp leaves it
// out, and the authenticated claims admit a resource only with its owner.
func TestAnOwnerSelectedScopeNeverReadsAsTheWholeKind(t *testing.T) {
	a := hoptest.New(t)
	token := a.Issue(t, "documents", ownedScope(t, "documents", "read", "principal-u"))
	id, err := verifier(t, a, "documents").Verify(context.Background(), hoptest.Forward(t, token, proof))
	if err != nil {
		t.Fatalf("a capability with an owner-selected scope must verify: %v", err)
	}
	if id.Has("documents", "read") || slices.Contains(id.Scopes, "documents:read") {
		t.Fatalf("the hop stamped an owner-selected scope as whole-kind documents:read (%v)", id.Scopes)
	}
	if id.Claims.Allows("documents", "read", "") || id.Claims.Allows("documents", "read", "any") {
		t.Fatal("Claims.Allows admits an owner-selected scope without the resource's owner")
	}
	// The scope is not stripped: the module admits the owner's resources.
	owned, ok := any(id.Claims).(interface {
		AllowsOwned(kind, action, resourceID, ownerID string) bool
	})
	if !ok || !owned.AllowsOwned("documents", "read", "any", "principal-u") || owned.AllowsOwned("documents", "read", "any", "principal-v") {
		t.Fatal("the hop's claims must admit the owner's resource and refuse another owner's")
	}
}
