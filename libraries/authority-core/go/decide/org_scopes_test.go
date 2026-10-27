package decide_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

var store = domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule,
	ResourceKinds: []*basev0.WorkScopeV1{sc("collection", "read", "write"), sc("note", "read")}}

func role(scopes ...domain.RoleScope) []domain.OrgRole {
	return []domain.OrgRole{{Organization: "acme", Name: "r", Scopes: scopes}}
}

func collectionRead(grants ...resources.Grant) domain.RoleScope {
	return domain.RoleScope{Kind: "collection", Actions: []string{"read"}, Resources: grants}
}

func ids(actions []string, of ...string) []*basev0.WorkScopeV1 {
	return []*basev0.WorkScopeV1{owned("collection", "", actions, of...)}
}

func same(t *testing.T, got, want []*basev0.WorkScopeV1) {
	t.Helper()
	if !scope.Same(got, scope.Normalize(want)) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A role naming resources by id holds exactly those ids: an empty ask is
// issued on them, never on the whole kind.
func TestAResourceScopedRoleHoldsExactlyItsIDs(t *testing.T) {
	held := decide.OrgScopes(role(collectionRead(resources.Grant{ID: "store-x"}, resources.Grant{ID: "store-z"})), store, nil)
	same(t, held, ids([]string{"read"}, "store-x", "store-z"))
	issued, err := decide.Issue(nil, held)
	if err != nil {
		t.Fatal(err)
	}
	same(t, issued, ids([]string{"read"}, "store-x", "store-z"))
	if issued, err = decide.Issue(ids([]string{"read"}, "store-x"), held); err != nil {
		t.Fatal(err)
	}
	same(t, issued, ids([]string{"read"}, "store-x"))
}

// An ask naming any id the role does not select, or the whole kind, is
// refused by name, even beside an id it does select.
func TestAnAskBeyondARolesIDsIsRefused(t *testing.T) {
	roles := role(collectionRead(resources.Grant{ID: "store-x"}))
	for name, ask := range map[string][]*basev0.WorkScopeV1{
		"another id":         ids([]string{"read"}, "store-y"),
		"a held and another": ids([]string{"read"}, "store-x", "store-y"),
		"the whole kind":     {sc("collection", "read")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decide.Issue(ask, decide.OrgScopes(roles, store, ask))
			refused(t, err, domain.Denied, "widens")
		})
	}
}

// A hop's ceiling is what the person holds now, read against its ask and its
// parent's ids: a child naming an id the person does not hold is not within it.
func TestAChildCannotWidenAResourceScopedRole(t *testing.T) {
	roles := role(collectionRead(resources.Grant{ID: "store-x"}))
	parent, _ := decide.Issue(nil, decide.OrgScopes(roles, store, nil))
	for _, ask := range [][]*basev0.WorkScopeV1{ids([]string{"read"}, "store-y"), {sc("collection", "read")}} {
		ceiling := scope.Intersect(decide.OrgScopes(roles, store, append(ask, parent...)), parent)
		if scope.Attenuates(ask, ceiling) {
			t.Fatalf("a child asking %v is within %v", ask, ceiling)
		}
	}
	same(t, scope.Intersect(decide.OrgScopes(roles, store, parent), parent), ids([]string{"read"}, "store-x"))
}

// A token cannot carry a prefix or a pattern, so neither ever holds the whole
// kind: it holds only the ids an ask (or a parent) names that it matches. An
// empty ask therefore carries none of it; this is the fail-closed choice, and
// a person holding nothing else is refused by name.
func TestAPatternOrPrefixRoleFailsClosed(t *testing.T) {
	roles := role(collectionRead(resources.Grant{Prefix: "derived/"}, resources.Grant{Pattern: "shared-[a-z]+"}))
	held := decide.OrgScopes(roles, store, nil)
	if len(held) != 0 {
		t.Fatalf("an empty ask holds %v of a pattern", held)
	}
	_, err := decide.Issue(nil, held)
	refused(t, err, domain.Denied, "holds nothing")

	ask := ids([]string{"read"}, "derived/wiki", "shared-finance")
	issued, err := decide.Issue(ask, decide.OrgScopes(roles, store, ask))
	if err != nil {
		t.Fatal(err)
	}
	same(t, issued, ask)

	ask = ids([]string{"read"}, "shared-finance", "finance")
	_, err = decide.Issue(ask, decide.OrgScopes(roles, store, ask))
	refused(t, err, domain.Denied, "widens")

	ask = []*basev0.WorkScopeV1{sc("collection", "read")}
	_, err = decide.Issue(ask, decide.OrgScopes(roles, store, ask))
	refused(t, err, domain.Denied, "beyond")

	// Ids named on another kind are not this kind's.
	if held := decide.OrgScopes(roles, store, []*basev0.WorkScopeV1{owned("note", "", []string{"read"}, "shared-finance")}); len(held) != 0 {
		t.Fatalf("a pattern holds %v from another kind's ids", held)
	}
	// Beside an id matcher, an empty ask carries the id alone.
	same(t, decide.OrgScopes(role(collectionRead(resources.Grant{Pattern: "shared-[a-z]+"}, resources.Grant{ID: "store-x"})), store, nil), ids([]string{"read"}, "store-x"))
	// A matcher that does not compile holds nothing.
	if held := decide.OrgScopes(role(collectionRead(resources.Grant{Pattern: "(a"})), store, ask); len(held) != 0 {
		t.Fatalf("an invalid matcher holds %v", held)
	}
}

// A role naming no resource, or every resource, holds the whole kind as before.
func TestAWholeKindRoleIsUnchanged(t *testing.T) {
	for name, scopes := range map[string]domain.RoleScope{
		"no matcher":    collectionRead(),
		"all":           collectionRead(resources.Grant{All: true}),
		"all and an id": collectionRead(resources.Grant{ID: "store-x"}, resources.Grant{All: true}),
	} {
		t.Run(name, func(t *testing.T) {
			held := decide.OrgScopes(role(scopes), store, nil)
			same(t, held, []*basev0.WorkScopeV1{sc("collection", "read")})
			issued, err := decide.Issue(nil, held)
			if err != nil {
				t.Fatal(err)
			}
			same(t, issued, []*basev0.WorkScopeV1{sc("collection", "read")})
		})
	}
}

// One role holding the whole kind and another an id of it, for the same
// action: the person holds the whole kind, whichever comes first.
func TestAWholeKindRoleAbsorbsAResourceScopedOne(t *testing.T) {
	whole, scoped := collectionRead(), collectionRead(resources.Grant{ID: "store-x"})
	for _, roles := range [][]domain.OrgRole{
		{{Name: "a", Scopes: []domain.RoleScope{whole}}, {Name: "b", Scopes: []domain.RoleScope{scoped}}},
		{{Name: "b", Scopes: []domain.RoleScope{scoped}}, {Name: "a", Scopes: []domain.RoleScope{whole}}},
	} {
		same(t, decide.OrgScopes(roles, store, nil), []*basev0.WorkScopeV1{sc("collection", "read")})
	}
	// A different action keeps its own ids.
	writes := domain.RoleScope{Kind: "collection", Actions: []string{"write"}, Resources: []resources.Grant{{ID: "store-x"}}}
	same(t, decide.OrgScopes(role(whole, writes), store, nil), []*basev0.WorkScopeV1{sc("collection", "read"), owned("collection", "", []string{"write"}, "store-x")})
}

// A role scope on every kind naming an id holds that id on each served kind.
func TestAnAnyKindRoleNamingIDsHoldsThemOnEachKind(t *testing.T) {
	held := decide.OrgScopes(role(domain.RoleScope{Kind: scope.AnyKind, Actions: []string{"read"}, Resources: []resources.Grant{{ID: "x"}}}), store, nil)
	same(t, held, []*basev0.WorkScopeV1{owned("collection", "", []string{"read"}, "x"), owned("note", "", []string{"read"}, "x")})
}
