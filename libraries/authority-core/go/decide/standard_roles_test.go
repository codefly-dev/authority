package decide_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A module page declaring no roles derives the standard two from what it
// serves: the user reads and writes, the admin holds every action served —
// the rule an explicit declaration follows over its own kinds. A kind serving
// neither read nor write gives the user nothing there; a module serving
// nothing derives none; and the derived set passes the validator a declared
// set passes.
func TestTheStandardRolesAreDerivedFromWhatAPageServes(t *testing.T) {
	m := domain.Module{Name: "models", Principal: "models", Kind: domain.KindModule, Generation: 1, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("models.profiles", "invoke", "read"), sc("models.notes", "read", "write", "admin"), sc("models.jobs", "execute")}}
	got := decide.StandardRoles(m)
	want := map[string][]*basev0.WorkScopeV1{
		domain.UserRole:  {sc("models.notes", "read", "write"), sc("models.profiles", "read")},
		domain.AdminRole: {sc("models.jobs", "execute"), sc("models.notes", "admin", "read", "write"), sc("models.profiles", "invoke", "read")},
	}
	if len(got) != len(want) {
		t.Fatalf("derived %v, want %v", got, want)
	}
	for role, scopes := range want {
		if !scope.Same(got[role], scope.Normalize(scopes)) {
			t.Errorf("%s derived %v, want %v", role, got[role], scopes)
		}
	}
	m.Roles = got
	if err := decide.ValidateModule(m); err != nil {
		t.Fatalf("the derived roles do not pass the validator: %v", err)
	}
	if !decide.RoleGated(m) {
		t.Fatal("a page with derived roles is gated by them")
	}

	// A kind served at any action reads, writes and holds everything.
	any := decide.StandardRoles(domain.Module{ResourceKinds: []*basev0.WorkScopeV1{sc("x.item", scope.AnyAction)}})
	if len(any) != 2 ||
		!scope.Same(any[domain.UserRole], []*basev0.WorkScopeV1{sc("x.item", "read", "write")}) ||
		!scope.Same(any[domain.AdminRole], []*basev0.WorkScopeV1{sc("x.item", scope.AnyAction)}) {
		t.Fatalf("any action derived %v", any)
	}
	// Nothing readable or writable: no user, an admin of what is served.
	only := decide.StandardRoles(domain.Module{ResourceKinds: []*basev0.WorkScopeV1{sc("x.task", "execute")}})
	if _, ok := only[domain.UserRole]; ok || len(only) != 1 || len(only[domain.AdminRole]) != 1 {
		t.Fatalf("unreadable kinds derived %v", only)
	}
	if decide.StandardRoles(domain.Module{}) != nil {
		t.Fatal("a module serving nothing derives roles")
	}
}
