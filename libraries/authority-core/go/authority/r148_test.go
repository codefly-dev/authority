package authority_test

import (
	"context"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func storeModule(generation uint64) domain.Module {
	return domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: generation, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")}}
}

// M1: a module's installation is never uninstalled by an administrator (it is
// withdrawn); a routine delivery reactivates nothing an administrator cut.
func TestAModuleInstallationIsNeverUninstalled(t *testing.T) {
	h := newHarness(t)
	alex := h.admin(acme)
	refused(t, h.svc.Uninstall(h.ctx, &alex, acme, h.inst(acme, "store").ID), "never uninstalled")
	if err := h.svc.Uninstall(h.ctx, &alex, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	// A routine delivery of a solution leaves an uninstalled installation as it is.
	a := solution("a", true)
	a.Generation = 2
	if _, err := h.svc.ApplyModule(h.ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Seals().Seal(h.ctx, "maya", h.inst(acme, "a").ID); err == nil {
		t.Fatal("a delivery reactivated an uninstalled installation")
	}
	// The host's own setup may retire a module at one organization; a
	// routine delivery leaves it retired.
	if err := h.svc.Uninstall(h.ctx, nil, acme, h.inst(acme, "store").ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.ApplyModule(h.ctx, storeModule(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Seals().Seal(h.ctx, "maya", h.inst(acme, "store").ID); err == nil {
		t.Fatal("a delivery reactivated a module the host retired")
	}
}

// m1: a withdrawn module's principal is its own for life: no other module
// claims it, and no installation is given it.
func TestATombstonedPrincipalIsNeverClaimed(t *testing.T) {
	h := newHarness(t)
	if err := h.svc.WithdrawModule(h.ctx, "store"); err != nil {
		t.Fatal(err)
	}
	evil := storeModule(1)
	evil.Name = "evil"
	_, err := h.svc.ApplyModule(h.ctx, evil)
	code(t, err, domain.Denied)
	if _, err := h.svc.ApplyModule(h.ctx, storeModule(2)); err != nil {
		t.Fatalf("store's own redelivery: %v", err)
	}
	if err := h.svc.WithdrawModule(h.ctx, "store"); err != nil {
		t.Fatal(err)
	}
	cfg := h.cfg
	cfg.PrincipalID = func(string, string) string { return "store" }
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := h.admin(globex)
	_, err = svc.Install(h.ctx, &admin, globex, "b", "author", admin.ID, nil)
	code(t, err, domain.Denied)
}

// m2: a caller the store no longer knows, and a current member who
// administers nothing, cannot tell an installation from an absent one.
func TestNoOneButAnAdministratorTellsPresentFromAbsent(t *testing.T) {
	h := newHarness(t)
	present, absent := h.inst(acme, "a").ID, authority.StableInstallationID(acme, "never-installed")
	remi := h.person("remi")
	maya := h.person("maya")
	h.store.DeletePerson("maya")
	for _, id := range []string{present, absent} {
		want := "installation " + id + " belongs to another organization than \"acme\""
		for name, err := range map[string]error{
			"a member uninstalling": h.svc.Uninstall(h.ctx, &remi, acme, id),
			"a deleted ex-member":   h.svc.Uninstall(h.ctx, &maya, acme, id),
			"a deleted ex-member listing": func() error {
				_, err := h.svc.ListRoleGrants(h.ctx, maya, acme, id)
				return err
			}(),
		} {
			if err == nil || err.Error() != want {
				t.Fatalf("%s on %s: %v", name, id, err)
			}
		}
	}
}

type outage struct{ authority.Store }

type outageTx struct{ authority.Tx }

func (outageTx) GrantEpoch(string, string) (uint64, error) {
	return 0, errors.New("store unavailable")
}

func (o outage) Read(ctx context.Context, fn func(authority.Tx) error) error {
	return o.Store.Read(ctx, func(tx authority.Tx) error { return fn(outageTx{tx}) })
}

// m3: a store failure during issuance is reported as itself, not as a
// refusal.
func TestAnIssueReportsAStoreOutage(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	svc, err := authority.New(outage{h.store}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.IssueForPerson(h.ctx, h.person("maya"), authority.IssueRequest{Audience: "a"})
	if err == nil {
		t.Fatal("issued through an outage")
	}
	if _, refusal := domain.CodeOf(err); refusal {
		t.Fatalf("an outage reads as a refusal: %v", err)
	}
}
