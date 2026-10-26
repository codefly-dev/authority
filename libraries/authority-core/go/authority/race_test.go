package authority_test

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// racing is a store that, once armed, runs a change right after the first
// read that decided from role grants: the window between an issuance's
// decision and its mint.
type racing struct {
	authority.Store
	change func()
}

type grantsTx struct {
	authority.Tx
	read *bool
}

func (t grantsTx) RoleGrants(id string) ([]domain.RoleGrant, error) {
	*t.read = true
	return t.Tx.RoleGrants(id)
}

func (r *racing) Read(ctx context.Context, fn func(authority.Tx) error) error {
	read := false
	err := r.Store.Read(ctx, func(tx authority.Tx) error { return fn(grantsTx{tx, &read}) })
	if read && r.change != nil {
		change := r.change
		r.change = nil
		change()
	}
	return err
}

// raced is a service over the harness's store whose next grant-deciding read
// is followed by change.
func (h *harness) raced(change func()) *authority.Service {
	h.t.Helper()
	svc, err := authority.New(&racing{Store: h.store, change: change}, h.cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return svc
}

// B1: a revoke or a team leave committing between an issuance's decision and
// its mint never yields a capability: the mint is refused, in each path that
// decides from current grants.
func TestARevokeRacingAnIssueYieldsNoCapability(t *testing.T) {
	revoke := func(h *harness) func() { return func() { h.revoke("a", "viewer", "maya", "") } }
	leave := func(h *harness) func() {
		return func() {
			h.store.PutPerson(domain.Person{ID: "maya", Organization: acme})
			if err := h.svc.PersonChanged(h.ctx, "maya"); err != nil {
				h.t.Fatal(err)
			}
		}
	}
	for name, setup := range map[string]struct {
		grant  func(h *harness)
		change func(h *harness) func()
	}{
		"a revoked role": {func(h *harness) { h.grant("a", "viewer", "maya") }, revoke},
		"a team left": {func(h *harness) {
			h.store.PutPerson(domain.Person{ID: "maya", Organization: acme, Teams: []string{"team"}})
			h.grantTeam("a", "viewer", "team")
		}, leave},
	} {
		t.Run(name+" racing a person's issue", func(t *testing.T) {
			h := newHarness(t)
			setup.grant(h)
			svc := h.raced(setup.change(h))
			out, err := svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "a"})
			noCapability(t, h, out, err)
		})
		t.Run(name+" racing a child", func(t *testing.T) {
			h := newHarness(t)
			setup.grant(h)
			root := h.must(h.root("maya", "a"))
			svc := h.raced(setup.change(h))
			out, err := svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			noCapability(t, h, out, err)
		})
		t.Run(name+" racing a delegation", func(t *testing.T) {
			h := newHarness(t)
			setup.grant(h)
			d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), read)}, "x")
			if err != nil {
				t.Fatal(err)
			}
			svc := h.raced(setup.change(h))
			out, err := svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
			noCapability(t, h, out, err)
		})
	}
}

func noCapability(t *testing.T, h *harness, out authority.Issued, err error) {
	t.Helper()
	if err != nil {
		return
	}
	if cerr := h.check(out); cerr == nil {
		t.Fatalf("a capability minted across the change checks: %v", out.Context.GetAuthorityScopes())
	}
}

// B2: a hop the installation made for itself through another module, refused
// once it is uninstalled, stays refused after a reinstall, even one holding a
// narrower role.
func TestAnUninstalledAgentsHopStaysDeadAfterReinstall(t *testing.T) {
	h := newHarness(t)
	agent := h.must(h.agent("a", "store"))
	deeper := h.must(h.hop(agent, "self"))
	if err := h.check(deeper); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UninstallAsHost(h.ctx, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	if h.check(deeper) == nil {
		t.Fatal("the uninstalled agent's hop checks")
	}
	admin := h.admin(acme)
	if _, err := h.svc.Install(h.ctx, admin, acme, "a", "viewer", admin.ID, nil); err != nil {
		t.Fatal(err)
	}
	if h.check(deeper) == nil {
		t.Fatal("the reinstall revived the old agent's hop")
	}
}

// M1: a person's hop through the solution, sealed to another module's
// installation, ends with the uninstall.
func TestAnUninstallEndsEveryHopThroughTheSolution(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	deeper := h.must(h.hop(h.must(h.through("maya", "a", "store")), "self"))
	if err := h.check(deeper); err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UninstallAsHost(h.ctx, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	if h.check(deeper) == nil {
		t.Fatal("a hop through the uninstalled solution checks")
	}
}

// m1: an installation issue naming another organization's installation and
// one naming none answer alike, with the id as asked.
func TestAnInstallationIssueAnswersForeignAsAbsent(t *testing.T) {
	h := newHarness(t)
	foreign := h.inst(globex, "a").ID
	_, errForeign := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, foreign, authority.IssueRequest{Organization: acme, Audience: "a"})
	_, errAbsent := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "a"}, "no-such", authority.IssueRequest{Organization: acme, Audience: "a"})
	code(t, errForeign, domain.Denied)
	code(t, errAbsent, domain.Denied)
	if errForeign.Error() != "installation "+foreign+" belongs to another organization than \"acme\"" ||
		errAbsent.Error() != "installation no-such belongs to another organization than \"acme\"" {
		t.Fatalf("foreign %q, absent %q", errForeign, errAbsent)
	}
}

// m4: Check verifies before it reads anything: a forged capability naming an
// owner and a binding is refused as unverified, never answered from the store.
func TestCheckVerifiesBeforeItReads(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	out := h.must(h.through("maya", "a", "store"))
	forged := out.Token[:len(out.Token)-4] + "AAAA"
	_, _, err := h.svc.Check(h.ctx, forged, "store")
	if err == nil || strings.Contains(err.Error(), "owner-aware") {
		t.Fatalf("a forged capability was answered from the store: %v", err)
	}
}
