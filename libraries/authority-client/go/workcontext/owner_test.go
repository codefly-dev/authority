package workcontext_test

import (
	"testing"

	reader "github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// ownedScope is {kind, [action], resource_owner_id: owner, resource_ids: ids}.
func ownedScope(t *testing.T, kind, action, owner string, ids ...string) *basev0.WorkScopeV1 {
	t.Helper()
	return &basev0.WorkScopeV1{ResourceKind: kind, Actions: []string{action}, ResourceIds: ids, ResourceOwnerId: owner}
}

// The owner-selected rows (Allows refusing, AllowsOwned admitting only the
// owner) are the shared fixture's "owner-selected" entry, which TestCoreFixtures
// runs here and the Python and TypeScript readers run on the same rows.

// ownerOf reads WorkScopeV1 field 4 from scope's encoding, known or not.
func ownerOf(t *testing.T, scope *basev0.WorkScopeV1) string {
	t.Helper()
	raw, err := proto.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	for len(raw) > 0 {
		number, kind, n := protowire.ConsumeTag(raw)
		if n < 0 {
			t.Fatal("unreadable scope")
		}
		raw = raw[n:]
		if number == 4 && kind == protowire.BytesType {
			value, m := protowire.ConsumeString(raw)
			if m < 0 {
				t.Fatal("unreadable owner")
			}
			return value
		}
		m := protowire.ConsumeFieldValue(number, kind, raw)
		if m < 0 {
			t.Fatal("unreadable scope")
		}
		raw = raw[m:]
	}
	return ""
}

// Scopes() never hands a module an owner-selected scope as the whole
// kind: each it returns keeps its resource owner.
func TestScopesKeepTheirResourceOwner(t *testing.T) {
	c := body(t, "session")
	c.AuthorityScopes = []*basev0.WorkScopeV1{ownedScope(t, "record", "read", "principal-u"), {ResourceKind: "plain", Actions: []string{"read"}}}
	scopes := read(t, c).Scopes()
	if len(scopes) != 2 {
		t.Fatalf("Scopes() returned %d scopes, want 2", len(scopes))
	}
	for _, scope := range scopes {
		want := map[string]string{"record": "principal-u", "plain": ""}[scope.GetResourceKind()]
		if got := ownerOf(t, scope); got != want {
			t.Fatalf("Scopes() returned %s owned by %q, want %q", scope.GetResourceKind(), got, want)
		}
	}
}

// A signed chain whose hop drops or changes the resource owner is a widening:
// it is refused, while a hop narrowing within the owner verifies.
func TestAChainThatDropsOrChangesTheOwnerIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		last *basev0.WorkScopeV1
		ok   bool
	}{
		"narrowed within the owner": {&basev0.WorkScopeV1{ResourceKind: "record", Actions: []string{"read"}, ResourceIds: []string{"r1"}, ResourceOwnerId: "principal-u"}, true},
		"the owner dropped":         {&basev0.WorkScopeV1{ResourceKind: "record", Actions: []string{"read"}}, false},
		"the owner changed":         {&basev0.WorkScopeV1{ResourceKind: "record", Actions: []string{"read"}, ResourceOwnerId: "principal-v"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			c := body(t, "delegated")
			owned := &basev0.WorkScopeV1{ResourceKind: "record", Actions: []string{"read"}, ResourceOwnerId: "principal-u"}
			c.AuthorityScopes = []*basev0.WorkScopeV1{owned}
			for _, actor := range c.ActorChain {
				actor.GrantedScopes = []*basev0.WorkScopeV1{owned}
			}
			c.ActorChain[len(c.ActorChain)-1].GrantedScopes = []*basev0.WorkScopeV1{tc.last}
			_, err := reader.Authenticate(stampedToken(tokenFor(t, c)), "test-proof", c.GetAudience(), trustFor(c))
			if (err == nil) != tc.ok {
				t.Fatalf("authenticate: %v", err)
			}
		})
	}
}
