package decide_test

import (
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// policySolution is a solution declaring all that core's contract reader
// once held to authorization rules: roles, a governing scope, and bindings a
// person's capability travels (store), one no person is in (jobs), and one
// addressed to the solution itself (self).
func policySolution() domain.Module {
	return domain.Module{Name: "notes", Principal: "notes", Kind: domain.KindSolution, Generation: 1,
		ResourceKinds: []*basev0.WorkScopeV1{rsc("notes.page", "publish", "read", "write")},
		Bindings: map[string]domain.Binding{
			"store": {ID: "store", Audience: "store", InvokeScopes: []*basev0.WorkScopeV1{rsc("store.item", "read")}},
			"jobs":  {ID: "jobs", Audience: "jobs", HeadlessScopes: []*basev0.WorkScopeV1{rsc("jobs.run", "start")}},
			"self":  {ID: "self", Audience: "notes", InvokeScopes: []*basev0.WorkScopeV1{rsc("notes.page", "read")}},
		},
		Roles: map[string][]*basev0.WorkScopeV1{
			domain.AdminRole: {rsc("notes.page", "publish", "read", "write")},
			domain.UserRole:  {rsc("notes.page", "read"), rsc("store.item", "read")},
		},
		SourceGovernance: []*basev0.WorkScopeV1{rsc("notes.page", "write")},
	}
}

// through has role reach kind through binding, as a delivery reads it: the
// scope in the role and how it is reached.
func through(m *domain.Module, role, binding string, scope *basev0.WorkScopeV1) {
	m.Roles[role] = append(m.Roles[role], scope)
	m.Through = map[string]map[string][]*basev0.WorkScopeV1{role: {binding: {scope}}}
}

// Every authorization rule core's contract reader held before codefly-dev/core
// v0.19.32 is the host's: one row per conformance fixture core deleted, the
// same declaration refused where a delivery is read (PageRoles) or composed
// (ValidateModule), naming why. The "installer" core refused by name is refused
// here as any name that is neither admin nor user (role_names_test.go).
func TestTheHostHoldsWhatCoresReaderNoLongerDoes(t *testing.T) {
	if err := hostRefusal(policySolution()); err != nil {
		t.Fatalf("the base declaration is refused: %v", err)
	}
	for fixture, tc := range map[string]struct {
		change  func(*domain.Module)
		refusal string
	}{
		"role-named-viewer":   {func(m *domain.Module) { m.Roles["viewer"] = m.Roles[domain.UserRole] }, `declares role "viewer", which is neither "admin" nor "user"`},
		"role-without-user":   {func(m *domain.Module) { delete(m.Roles, domain.UserRole) }, `none is "user"`},
		"role-without-admin":  {func(m *domain.Module) { delete(m.Roles, domain.AdminRole) }, `none is "admin"`},
		"role-grants-nothing": {func(m *domain.Module) { m.Roles[domain.UserRole] = nil }, `role "user" of notes grants nothing`},
		"role-through-headless-binding": {func(m *domain.Module) { through(m, domain.UserRole, "jobs", rsc("jobs.run", "start")) },
			`through binding "jobs", which carries nothing for a person`},
		"role-through-self-binding": {func(m *domain.Module) { through(m, domain.UserRole, "self", rsc("notes.page", "read")) },
			`through binding "self", which is addressed to notes itself`},
		"role-through-own-kind": {func(m *domain.Module) { through(m, domain.UserRole, "store", rsc("notes.page", "read")) },
			`names notes.page through binding "store", a kind notes serves itself`},
		"role-beyond-own-ceiling": {func(m *domain.Module) {
			m.Roles[domain.UserRole] = append(m.Roles[domain.UserRole], rsc("notes.page", "delete"))
		}, `role "user" of notes grants beyond what notes serves`},
		"role-beyond-consumption": {func(m *domain.Module) {
			m.Roles[domain.UserRole] = append(m.Roles[domain.UserRole], rsc("store.item", "write"))
		}, `role "user" of notes grants beyond what notes serves`},
		"role-headless-permission": {func(m *domain.Module) {
			m.Roles[domain.UserRole] = append(m.Roles[domain.UserRole], rsc("jobs.run", "start"))
		}, `role "user" of notes grants beyond what notes serves`},
		"role-installation-owned-beyond-consumption": {func(m *domain.Module) {
			m.OwnedRoles = map[string][]*basev0.WorkScopeV1{domain.UserRole: {rsc("store.item", "write")}}
		}, `installation-owned role "user" grants beyond what notes serves`},
		"source-governance-consumed-kind": {func(m *domain.Module) { m.SourceGovernance = []*basev0.WorkScopeV1{rsc("store.item", "read")} },
			"governs its sources by store.item, which is not a kind it declares"},
		"source-governance-binding-action": {func(m *domain.Module) {
			m.ResourceKinds = []*basev0.WorkScopeV1{rsc("notes.page", "publish", "read")}
			m.Bindings["pages"] = domain.Binding{ID: "pages", Audience: "pages", InvokeScopes: []*basev0.WorkScopeV1{rsc("notes.page", "write")}}
		}, "notes.page:write, which its own ceiling does not name on the whole kind"},
		"source-governance-shared-kind": {func(m *domain.Module) { m.SharedKinds = []string{"notes.page"} },
			"governs its sources by notes.page, which it declares shared"},
		"source-governance-ungranted": {func(m *domain.Module) {
			m.Roles[domain.AdminRole] = []*basev0.WorkScopeV1{rsc("notes.page", "publish", "read")}
		},
			"notes.page:write, which none of its roles grants"},
	} {
		t.Run(fixture, func(t *testing.T) {
			m := policySolution()
			tc.change(&m)
			if err := hostRefusal(m); err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("want a refusal naming %q, got %v", tc.refusal, err)
			}
		})
	}
}

// hostRefusal is the first refusal a host reaches for m: where the delivery
// is read, then where it is composed.
func hostRefusal(m domain.Module) error {
	if err := decide.PageRoles(m); err != nil {
		return err
	}
	return decide.ValidateModule(m)
}

// A module page declaring no roles whose kinds serve neither read nor write
// derives admin alone (StandardRoles), so it is refused saying so, not as if
// it had declared one role.
func TestAPageDerivingNoUserIsToldToDeclareItsRoles(t *testing.T) {
	m := domain.Module{Name: "dials", Principal: "dials", Kind: domain.KindModule, Generation: 1, Page: true,
		ResourceKinds: []*basev0.WorkScopeV1{rsc("dials.dial", "invoke")}}
	m.Roles = decide.StandardRoles(m)
	if err := decide.PageRoles(m); err == nil || !strings.Contains(err.Error(), `derives "user" only from a kind it serves read or write on`) {
		t.Fatalf("a page deriving no user: %v", err)
	}
}
