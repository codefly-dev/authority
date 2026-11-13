package authority_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A module that defines data at a module that checks owners through a headless
// scope is the data's owner: the scope is owner-selected to the module's
// installation, as its page's roles are (RBAC-1), so what it defines is born
// owned by that installation and the same installation's page reads it back.
// A whole-kind headless scope defined unowned data that no owner-scoped read
// could ever reach.
func TestAModulesHeadlessDefineAtAnOwnerAwareModuleIsBornOwnedAndItsPageReadsItBack(t *testing.T) {
	h := newHarness(t)
	pageReachingTheStore(t, h)
	var m domain.Module
	if err := h.store.Read(h.ctx, func(tx authority.Tx) (err error) { m, err = tx.ModuleNamed("pages"); return err }); err != nil {
		t.Fatal(err)
	}
	m.Generation++
	m.Bindings["define"] = domain.Binding{ID: "define", Audience: "store", HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "write")}}
	m.Bindings["shared-define"] = domain.Binding{ID: "shared-define", Audience: "profiles", HeadlessScopes: []*basev0.WorkScopeV1{sc("profiles.profile", "write")}}
	m.Bindings["legacy-define"] = domain.Binding{ID: "legacy-define", Audience: "legacy-store", HeadlessScopes: []*basev0.WorkScopeV1{sc(legacyKind, "write")}}
	m.Bindings["read-kind"] = domain.Binding{ID: "read-kind", Audience: "store", HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read")}}
	m.Bindings["read-and-define"] = domain.Binding{ID: "read-and-define", Audience: "store", HeadlessScopes: []*basev0.WorkScopeV1{sc(kind, "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	mine := h.principal(acme, "pages")
	define := func(binding string, org string, scopes ...*basev0.WorkScopeV1) (authority.Issued, error) {
		return h.svc.IssueForWorkload(h.ctx, authority.Workload{Module: "pages"}, authority.IssueRequest{Binding: binding, Operation: "headless", Organization: org, Scopes: scopes})
	}

	t.Run("the define is the installation's, and its own page reads exactly that owner", func(t *testing.T) {
		exactly(t, h.must(define("define", acme)), kind, mine, []string{"write"})
		exactly(t, h.must(define("define", acme, sc(kind, "write"))), kind, mine, []string{"write"})
		read := h.must(h.page("maya", "pages", "store"))
		exactly(t, read, kind, mine, []string{"read"})
	})
	// A read stays kind-wide, for a module reading across owners at a module
	// that honours a scope naming no owner; and it is ALSO selected to the
	// module's own installation, for a module that honours only owner-selected
	// scopes (the record store, RBAC-4a: an ownerless scope reaches nothing
	// there). Without the selected row a module reads back nothing it defined:
	// the directory's GetRecordType of its own types was refused on blue,
	// "the call holds no records.types scope with read selected to that owner".
	t.Run("a kind-wide read creates nothing and stays kind-wide, and also reaches the module's own installation's data", func(t *testing.T) {
		rows(t, h.must(define("read-kind", acme)), map[string]string{"": "read", mine: "read"})
	})
	t.Run("a scope that reads and creates is split: the read as declared and on its own data, the creating action owned", func(t *testing.T) {
		rows(t, h.must(define("read-and-define", acme)), map[string]string{"": "read", mine: "read,write"})
	})
	t.Run("a define owned by someone else is refused", func(t *testing.T) {
		_, err := define("define", acme, owned(kind, h.principal(acme, "a"), []string{"write"}))
		refused(t, err, "widens")
	})
	t.Run("a kind the audience shares, and a module that checks no owner, are unselected as before", func(t *testing.T) {
		exactly(t, h.must(define("shared-define", acme)), "profiles.profile", "", []string{"write"})
		exactly(t, h.must(define("legacy-define", acme)), legacyKind, "", []string{"write"})
	})
	t.Run("an installation recorded without a principal is refused, naming why, rather than defining unowned data", func(t *testing.T) {
		inst := h.pagesAt(acme)
		inst.PrincipalID = ""
		if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutInstallation(inst) }); err != nil {
			t.Fatal(err)
		}
		_, err := define("define", acme)
		refused(t, err, "would be born unowned")
		// No principal owns nothing: the read stays kind-wide alone.
		exactly(t, h.must(define("read-kind", acme)), kind, "", []string{"read"})
		exactly(t, h.must(define("legacy-define", acme)), legacyKind, "", []string{"write"})
	})
}

// rows requires the effective scopes of kind to be exactly one row per owner
// in want, each holding the comma-joined actions given.
func rows(t *testing.T, i authority.Issued, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, s := range effective(i) {
		if s.GetResourceKind() != kind || len(s.GetActions()) == 0 {
			t.Fatalf("effective %v, want only %s rows %v", effective(i), kind, want)
		}
		if _, dup := got[s.GetResourceOwnerId()]; dup {
			t.Fatalf("effective %v, want one row per owner %v", effective(i), want)
		}
		actions := slices.Clone(s.GetActions())
		slices.Sort(actions)
		got[s.GetResourceOwnerId()] = strings.Join(actions, ",")
	}
	if !maps.Equal(got, want) {
		t.Fatalf("effective %v, want rows by owner %v", effective(i), want)
	}
}
