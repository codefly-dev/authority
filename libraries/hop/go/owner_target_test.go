package hop_test

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/codefly-dev/authority/libraries/hop/go/hoptest"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// ownedScope is {kind, [action], resource_owner_id: owner, resource_ids: ids},
// with the owner selector written as WorkScopeV1 field 4: the target's field,
// carried as an unknown field until core declares it.
func ownedScope(t *testing.T, kind, action, owner string, ids ...string) *basev0.WorkScopeV1 {
	t.Helper()
	raw, err := proto.Marshal(&basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}, ResourceIds: ids})
	if err != nil {
		t.Fatal(err)
	}
	raw = protowire.AppendString(protowire.AppendTag(raw, 4, protowire.BytesType), owner)
	out := &basev0.WorkScopeV1{}
	if err := proto.Unmarshal(raw, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TARGET (solution principal; conformance RunSolutionPrincipalTarget): run
// with AUTHORITY_TARGET=solution-principal. A module fronted by the hop must
// never read an owner-selected scope as the whole kind: the stamp leaves it
// out, and the authenticated claims admit a resource only with its owner.
func TestAnOwnerSelectedScopeNeverReadsAsTheWholeKind(t *testing.T) {
	if os.Getenv("AUTHORITY_TARGET") != "solution-principal" {
		t.Skip("target contract, not yet implemented: run with AUTHORITY_TARGET=solution-principal")
	}
	a := hoptest.New(t)
	token := a.Issue(t, "documents", ownedScope(t, "documents", "read", "principal-u"))
	id, err := verifier(t, a, "documents").Verify(context.Background(), hoptest.Forward(t, token, proof))
	if err != nil {
		t.Fatalf("target: a capability with an owner-selected scope must verify: %v", err)
	}
	if id.Has("documents", "read") || slices.Contains(id.Scopes, "documents:read") {
		t.Fatalf("target: the hop stamped an owner-selected scope as whole-kind documents:read (%v)", id.Scopes)
	}
	if id.Claims.Allows("documents", "read", "") || id.Claims.Allows("documents", "read", "any") {
		t.Fatal("target: Claims.Allows admits an owner-selected scope without the resource's owner")
	}
}
