package authority_test

import (
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
		exactly(t, h.must(define("legacy-define", acme)), legacyKind, "", []string{"write"})
	})
}
