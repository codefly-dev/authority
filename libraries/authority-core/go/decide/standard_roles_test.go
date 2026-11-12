package decide_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A module page declaring no roles derives the standard three from what it
// serves: the viewer reads, the editor reads and writes, the installer holds
// every action served — the rule an explicit declaration follows over its
// own kinds. A kind nobody can read derives no viewer there; a module
// serving nothing derives none; and the derived set passes the validator a
// declared set passes.
func TestTheStandardRolesAreDerivedFromWhatAPageServes(t *testing.T) {
	m := domain.Module{Name: "models", Principal: "models", Kind: domain.KindModule, Generation: 1, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc("models.profiles", "invoke", "read"), sc("models.notes", "read", "write", "admin"), sc("models.jobs", "execute")}}
	got := decide.StandardRoles(m)
	want := map[string][]*basev0.WorkScopeV1{
		decide.ViewerRole:    {sc("models.notes", "read"), sc("models.profiles", "read")},
		decide.EditorRole:    {sc("models.notes", "read", "write"), sc("models.profiles", "read")},
		domain.InstallerRole: {sc("models.jobs", "execute"), sc("models.notes", "admin", "read", "write"), sc("models.profiles", "invoke", "read")},
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
	if !scope.Same(any[decide.ViewerRole], []*basev0.WorkScopeV1{sc("x.item", "read")}) ||
		!scope.Same(any[decide.EditorRole], []*basev0.WorkScopeV1{sc("x.item", "read", "write")}) ||
		!scope.Same(any[domain.InstallerRole], []*basev0.WorkScopeV1{sc("x.item", scope.AnyAction)}) {
		t.Fatalf("any action derived %v", any)
	}
	// Nothing readable: no viewer, no editor, an installer of what is served.
	only := decide.StandardRoles(domain.Module{ResourceKinds: []*basev0.WorkScopeV1{sc("x.task", "execute")}})
	if _, ok := only[decide.ViewerRole]; ok || len(only) != 1 || len(only[domain.InstallerRole]) != 1 {
		t.Fatalf("unreadable kinds derived %v", only)
	}
	if decide.StandardRoles(domain.Module{}) != nil {
		t.Fatal("a module serving nothing derives roles")
	}
}
