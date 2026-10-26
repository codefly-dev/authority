package workcontext_test

import (
	"os"
	"testing"

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

// ownerChecker is the target's owner-aware question: may the claims act with
// action on resourceID of kind, whose owner is ownerID?
type ownerChecker interface {
	AllowsOwned(kind, action, resourceID, ownerID string) bool
}

// TARGET (solution principal; conformance RunSolutionPrincipalTarget): run
// with AUTHORITY_TARGET=solution-principal. Claims take the resource's owner
// and refuse a mismatch; the owner-blind Allows never admits an owner-selected
// scope; an owner with ids admits only when both match.
func TestClaimsAdmitAnOwnerSelectedScopeOnlyForItsOwner(t *testing.T) {
	if os.Getenv("AUTHORITY_TARGET") != "solution-principal" {
		t.Skip("target contract, not yet implemented: run with AUTHORITY_TARGET=solution-principal")
	}
	c := body(t, "session")
	c.AuthorityScopes = []*basev0.WorkScopeV1{ownedScope(t, "record", "read", "principal-u"), ownedScope(t, "note", "read", "principal-u", "n1")}
	claims := read(t, c)
	if claims.Allows("record", "read", "") || claims.Allows("record", "read", "r1") || claims.Allows("note", "read", "n1") {
		t.Fatal("target: the owner-blind Allows admits an owner-selected scope")
	}
	owned, ok := any(claims).(ownerChecker)
	if !ok {
		t.Fatal("target: Claims has no AllowsOwned(kind, action, resourceID, ownerID)")
	}
	for _, q := range []struct {
		kind, id, owner string
		allowed         bool
	}{
		{"record", "r1", "principal-u", true}, {"record", "r1", "principal-v", false}, {"record", "r1", "", false},
		{"note", "n1", "principal-u", true}, {"note", "n2", "principal-u", false}, {"note", "n1", "principal-v", false},
	} {
		if owned.AllowsOwned(q.kind, "read", q.id, q.owner) != q.allowed {
			t.Fatalf("target: AllowsOwned(%s, read, %s, %s) want %v", q.kind, q.id, q.owner, q.allowed)
		}
	}
}
