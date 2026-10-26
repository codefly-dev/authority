package authority_test

import (
	"context"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
)

// M-a: a caller of another organization learns nothing of the one it names:
// an installation it has and one it has not answer alike, in Uninstall and
// in every role call, before anything is read.
func TestAnOutsiderCannotTellInstalledFromAbsent(t *testing.T) {
	h := newHarness(t)
	zoe := h.person("zoe")
	present, absent := h.inst(acme, "a").ID, authority.StableInstallationID(acme, "never-installed")
	answer := func(err error, id string) string {
		t.Helper()
		code(t, err, domain.Denied)
		want := "installation " + id + " belongs to another organization than \"acme\""
		if err.Error() != want {
			t.Fatalf("got %q, want %q", err, want)
		}
		return want
	}
	answer(h.svc.Uninstall(h.ctx, zoe, acme, present), present)
	answer(h.svc.Uninstall(h.ctx, zoe, acme, absent), absent)
	for _, id := range []string{present, absent} {
		_, err := h.svc.ListRoleGrants(h.ctx, zoe, acme, id)
		answer(err, id)
		_, err = h.svc.GrantRole(h.ctx, zoe, authority.RoleRequest{Organization: acme, InstallationID: id, Role: "viewer", PersonID: "dev"})
		answer(err, id)
		_, err = h.svc.RevokeRole(h.ctx, zoe, authority.RoleRequest{Organization: acme, InstallationID: id, Role: "viewer", PersonID: "dev"})
		answer(err, id)
	}
}

// M-b: a module withdrawn and delivered again is installed again at every
// organization, at a revision above the one it was revoked at.
func TestAWithdrawnModuleDeliveredAgainIsInstalledAgain(t *testing.T) {
	h := newHarness(t)
	id := h.inst(acme, "store").ID
	before, err := h.svc.Seals().Seal(h.ctx, "maya", id)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.WithdrawModule(h.ctx, "store"); err != nil {
		t.Fatal(err)
	}
	store := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 2, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")}}
	if _, err := h.svc.ApplyModule(h.ctx, store); err != nil {
		t.Fatal(err)
	}
	after, err := h.svc.Seals().Seal(h.ctx, "maya", id)
	if err != nil {
		t.Fatalf("the redelivered module is unreachable: %v", err)
	}
	if after.InstallationRevision <= before.InstallationRevision {
		t.Fatalf("the redelivered installation is at %d, was %d", after.InstallationRevision, before.InstallationRevision)
	}
}

// m-a: across withdrawal and redelivery, a module keeps its principal, its
// generation never rewinds, and the seal never goes back.
func TestAWithdrawnModuleKeepsItsPrincipalAndGeneration(t *testing.T) {
	h := newHarness(t)
	gen := uint64(1)
	apply := func(aware bool) {
		gen++
		m := solution("a", aware)
		m.Generation = gen
		if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	apply(false)
	apply(true)
	apply(false)
	before := h.seal("maya", "a")
	if err := h.svc.WithdrawModule(h.ctx, "a"); err != nil {
		t.Fatal(err)
	}
	renamed := solution("a", true)
	renamed.Principal, renamed.Generation = "a-renamed", gen+1
	_, err := h.svc.ApplyModule(h.ctx, renamed)
	code(t, err, domain.Denied)
	rewound := solution("a", true)
	rewound.Generation = 1
	_, err = h.svc.ApplyModule(h.ctx, rewound)
	code(t, err, domain.Precondition)
	again := solution("a", true)
	again.Generation = gen + 1
	if _, err := h.svc.ApplyModule(h.ctx, again); err != nil {
		t.Fatal(err)
	}
	h.install(acme, "a")
	if after := h.seal("maya", "a"); after <= before {
		t.Fatalf("the seal went from %d to %d", before, after)
	}
}

// m-b: an operation binding revoked by an uninstall stays revoked: the
// reinstalled installation's binding is another incarnation.
func TestARevokedBindingIsNeverRevived(t *testing.T) {
	h := newHarness(t)
	id := acme + "/a/store"
	before, err := h.svc.Seals().OperationBinding(h.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.UninstallAsHost(h.ctx, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	h.install(acme, "a")
	after, err := h.svc.Seals().OperationBinding(h.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revoked || after.Incarnation <= before.Incarnation {
		t.Fatalf("binding before %+v, after reinstall %+v", before, after)
	}
}

// m-c: a transaction that panics leaves nothing behind.
func TestAPanickingWriteLeavesNothing(t *testing.T) {
	store := memstore.New()
	store.PutOrganization(domain.Organization{ID: acme})
	func() {
		defer func() { _ = recover() }()
		_ = store.Write(context.Background(), func(tx authority.Tx) error {
			if err := tx.BumpAuthorizationRevision(acme); err != nil {
				return err
			}
			panic("mid-transaction")
		})
	}()
	_ = store.Read(context.Background(), func(tx authority.Tx) error {
		if rev, _ := tx.AuthorizationRevision(acme); rev != 1 {
			t.Fatalf("the panicking write's revision survived: %d", rev)
		}
		return nil
	})
}

// retrying meets one serialization conflict per write and retries fn, as the
// Store contract lets an adapter do.
type retrying struct{ *memstore.Store }

func (r retrying) Write(ctx context.Context, fn func(authority.Tx) error) error {
	conflicted := false
	for {
		err := r.Store.Write(ctx, func(tx authority.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			if !conflicted {
				conflicted = true
				return authority.ErrConflict
			}
			return nil
		})
		if !errors.Is(err, authority.ErrConflict) {
			return err
		}
	}
}

// m-d: a retried ApplyModule answers each installation once.
func TestApplyModuleIsSafeToRetry(t *testing.T) {
	h := newHarness(t)
	svc, err := authority.New(retrying{h.store}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 5, OwnerAware: true,
		ResourceKinds: []*basev0.WorkScopeV1{sc(kind, "admin", "create", "read", "write")}}
	ids, err := svc.ApplyModule(h.ctx, store)
	if err != nil || len(ids) != 2 {
		t.Fatalf("a retried apply answers %v (%v) for two organizations", ids, err)
	}
}

// m-e: a failed install step can be retried, and a different install of a
// pending target is refused naming the pending state.
func TestAFailedInstallStepCanBeRetried(t *testing.T) {
	h := newHarness(t)
	admin := h.admin(globex)
	down := func(context.Context, domain.Installation) error { return errors.New("step down") }
	approval := h.approval(globex, "b")
	if _, err := h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, approval, down); err == nil {
		t.Fatal("a failing step installed")
	}
	_, err := h.svc.Install(h.ctx, admin, globex, "b", "viewer", admin.ID, approval, nil)
	refused(t, err, "INSTALLATION_APPROVAL_OPERATION_CONFLICT")
	inst, err := h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, approval, nil)
	if err != nil || inst.Status != domain.Active {
		t.Fatalf("the retry: %+v %v", inst, err)
	}
}

// m-f: an installation's principal names no module, person or other
// installation, whatever principal source the host injects.
func TestAnInstallPrincipalIsItsOwn(t *testing.T) {
	for _, taken := range []string{"store", "maya"} {
		t.Run(taken, func(t *testing.T) {
			h := newHarness(t)
			cfg := h.cfg
			cfg.PrincipalID = func(string, string) string { return taken }
			svc, err := authority.New(h.store, cfg)
			if err != nil {
				t.Fatal(err)
			}
			admin := h.admin(globex)
			_, err = svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, h.approval(globex, "b"), nil)
			code(t, err, domain.Denied)
		})
	}
}

// failing is a store whose installation reads fail as an outage would.
type failing struct{ *memstore.Store }

type failingTx struct{ authority.Tx }

func (failingTx) Installation(string) (domain.Installation, error) {
	return domain.Installation{}, errors.New("store unavailable")
}

func (f failing) Read(ctx context.Context, fn func(authority.Tx) error) error {
	return f.Store.Read(ctx, func(tx authority.Tx) error { return fn(failingTx{tx}) })
}

// m-g: a store outage is reported as one, never as a missing installation.
func TestAStoreOutageIsNotANoSeal(t *testing.T) {
	h := newHarness(t)
	svc, err := authority.New(failing{h.store}, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Seals().Seal(h.ctx, "maya", h.inst(acme, "a").ID)
	if err == nil || errors.Is(err, workcontext.ErrNoSeal) {
		t.Fatalf("an outage answered %v", err)
	}
}
