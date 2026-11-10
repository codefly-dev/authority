package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// governedSolution is a solution whose editors govern its sources: the write
// its editor role alone grants on its own page kind.
func governedSolution() domain.Module {
	return domain.Module{Name: "notes", Principal: "notes", Kind: domain.KindSolution, Generation: 1, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{rsc("notes.page", "delete", "publish", "read", "write"), rsc("notes.profile", "read")},
		SharedKinds:   []string{"notes.profile"},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.InstallerRole: {rsc("notes.page", "read", "publish")},
			"editor":             {rsc("notes.page", "read", "write"), rsc("notes.profile", "read")},
			"viewer":             {rsc("notes.page", "read")},
		},
		SourceGovernance: []*basev0.WorkScopeV1{rsc("notes.page", "write")},
	}
}

// What a delivery declares governs its sources is held to its roles where it
// is applied, whatever the contract reader upstream already refused.
func TestAGoverningScopeIsAnOwnUnsharedKindARoleGrants(t *testing.T) {
	if err := decide.ValidateModule(governedSolution()); err != nil {
		t.Fatalf("the editors' write is refused: %v", err)
	}
	if err := decide.ValidateModule(func() domain.Module { m := governedSolution(); m.SourceGovernance = nil; return m }()); err != nil {
		t.Fatalf("a solution declaring no governance is refused: %v", err)
	}
	for _, tc := range []struct {
		name, refusal string
		governing     *basev0.WorkScopeV1
	}{
		{"another module's kind", "documents, which is not a kind it declares", rsc("documents", "write")},
		{"a shared kind", "notes.profile, which it declares shared", rsc("notes.profile", "read")},
		{"every action", `notes.page:"*"; a governing scope names one action`, rsc("notes.page", "*")},
		{"an empty action", `notes.page:""`, rsc("notes.page", "")},
		{"no action", "notes.page with no action", rsc("notes.page")},
		{"an action no role grants", "notes.page:delete, which none of its roles grants", rsc("notes.page", "delete")},
		{"an action its own ceiling does not name", "notes.page:archive, which its own ceiling does not name", rsc("notes.page", "archive")},
		{"resource ids", "with resource ids or an owner", &basev0.WorkScopeV1{ResourceKind: "notes.page", Actions: []string{"write"}, ResourceIds: []string{"one"}}},
		{"an owner", "with resource ids or an owner", &basev0.WorkScopeV1{ResourceKind: "notes.page", Actions: []string{"write"}, ResourceOwnerId: "someone"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := governedSolution()
			m.SourceGovernance = []*basev0.WorkScopeV1{tc.governing}
			err := decide.ValidateModule(m)
			if err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("want a refusal naming %q, got %v", tc.refusal, err)
			}
			if code, ok := domain.CodeOf(err); !ok || code != domain.Denied {
				t.Fatalf("want a denial, got %v", err)
			}
		})
	}
}

// A module page's installations are composed and never approved, so a
// governing scope it declared would take effect with no administrator having
// seen it: only a solution governs sources.
func TestOnlyASolutionGovernsSources(t *testing.T) {
	page := governedSolution()
	page.Kind, page.Page = domain.KindModule, true
	err := decide.ValidateModule(page)
	if err == nil || !strings.Contains(err.Error(), "only a solution, whose installations an administrator approves, governs sources") {
		t.Fatalf("a module page declaring a governing scope: %v", err)
	}
	page.SourceGovernance = nil
	if err := decide.ValidateModule(page); err != nil {
		t.Fatalf("a module page declaring none: %v", err)
	}
}

// A governing scope is held on the installation itself: one a role reaches
// downstream of a binding is refused, even beside a direct grant of it.
func TestAGoverningKindReachedThroughABindingIsRefused(t *testing.T) {
	m := governedSolution()
	m.Bindings = map[string]domain.Binding{"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{rsc("store.item", "read")}}}
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{"viewer": {"store": {rsc("notes.page", "write")}}}
	m.Roles["viewer"] = append(m.Roles["viewer"], rsc("notes.page", "write"))
	err := decide.ValidateModule(m)
	if err == nil || !strings.Contains(err.Error(), "which role viewer reaches through binding store") {
		t.Fatalf("a governing kind reached through a binding: %v", err)
	}
}

func TestGovernsAndGrantedByARole(t *testing.T) {
	m := governedSolution()
	if !decide.Governs(m, "notes.page", "write") || decide.Governs(m, "notes.page", "read") || decide.Governs(m, "documents", "write") {
		t.Fatal("Governs answers another declaration than the one made")
	}
	if !decide.GrantedByARole(m, "notes.page", "publish") || decide.GrantedByARole(m, "notes.page", "delete") {
		t.Fatal("GrantedByARole answers another grant than the roles make")
	}
}

// A governing action the own ceiling names only on some ids is not served on
// the whole kind: a later delivery lifting the ids — which no review covers —
// would activate it.
func TestAGoverningActionCeiledToSomeIdsIsRefused(t *testing.T) {
	m := governedSolution()
	m.ResourceKinds = []*basev0.WorkScopeV1{
		{ResourceKind: "notes.page", Actions: []string{"write"}, ResourceIds: []string{"one"}},
		rsc("notes.page", "read", "publish"), rsc("notes.profile", "read"),
	}
	// A binding underwrites the editors' whole-kind write, so the roles stay
	// valid and only the governing scope is at issue.
	m.Bindings = map[string]domain.Binding{"pages": {ID: "pages", Audience: "pages", InvokeScopes: []*basev0.WorkScopeV1{rsc("notes.page", "write")}}}
	err := decide.ValidateModule(m)
	if err == nil || !strings.Contains(err.Error(), "notes.page:write, which its own ceiling does not name on the whole kind") {
		t.Fatalf("a governing action ceiled to some ids: %v", err)
	}
}
