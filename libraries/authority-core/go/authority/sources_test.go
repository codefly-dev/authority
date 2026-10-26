package authority_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/memstore"
	"github.com/codefly-dev/core/workcontext"
)

// B2: an installation principal's epoch grows across uninstall and
// reinstall, so a capability sealed at an earlier incarnation never verifies
// again, whatever role the reinstall holds.
func TestAReinstallNeverRepeatsThePrincipalsEpoch(t *testing.T) {
	h := newHarness(t)
	u := h.principal(acme, "a")
	before, err := h.svc.Seals().PrincipalEpoch(h.ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Uninstall(h.ctx, nil, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Seals().PrincipalEpoch(h.ctx, u); err == nil {
		t.Fatal("an uninstalled principal has an epoch")
	}
	admin := h.admin(acme)
	if _, err := h.svc.Install(h.ctx, &admin, acme, "a", "viewer", admin.ID, nil); err != nil {
		t.Fatal(err)
	}
	after, err := h.svc.Seals().PrincipalEpoch(h.ctx, u)
	if err != nil || after <= before {
		t.Fatalf("the reinstalled principal's epoch is %d (%v), was %d", after, err, before)
	}
}

// M1: an uninstall moves its organization's authorization revision, so a
// hop through the solution sealed to another installation ends too.
func TestAnUninstallMovesItsOrganizationsRevision(t *testing.T) {
	h := newHarness(t)
	rev := func(org string) uint64 {
		r, err := h.svc.Revisions().AuthorizationRevision(h.ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	acmeBefore, globexBefore := rev(acme), rev(globex)
	if err := h.svc.Uninstall(h.ctx, nil, acme, h.inst(acme, "a").ID); err != nil {
		t.Fatal(err)
	}
	if rev(acme) <= acmeBefore || rev(globex) != globexBefore {
		t.Fatalf("acme %d→%d, globex %d→%d", acmeBefore, rev(acme), globexBefore, rev(globex))
	}
}

// M2: an uninstall is an administrator's act in the installation's own
// organization; another organization's installation answers as an absent
// one, and nothing changes.
func TestAnUninstallIsTheOrganizationsAdministrators(t *testing.T) {
	h := newHarness(t)
	id := h.inst(acme, "a").ID
	maya, zoe := h.person("maya"), h.person("zoe")
	refused(t, h.svc.Uninstall(h.ctx, &maya, acme, id), "administrator")
	foreign := h.svc.Uninstall(h.ctx, &zoe, globex, id)
	absent := h.svc.Uninstall(h.ctx, &zoe, globex, "no-such-installation")
	code(t, foreign, domain.Denied)
	if want := "installation " + id + " belongs to another organization than \"globex\""; foreign.Error() != want {
		t.Fatalf("foreign %q", foreign)
	}
	if want := "installation no-such-installation belongs to another organization than \"globex\""; absent.Error() != want {
		t.Fatalf("absent %q", absent)
	}
	if inst, err := h.svc.Installations(h.ctx, h.admin(acme), acme); err != nil || !activeIn(inst, id) {
		t.Fatalf("a refused uninstall changed %s: %v", id, err)
	}
	alex := h.admin(acme)
	if err := h.svc.Uninstall(h.ctx, &alex, acme, id); err != nil {
		t.Fatal(err)
	}
}

func activeIn(all []domain.Installation, id string) bool {
	for _, inst := range all {
		if inst.ID == id {
			return inst.Status == domain.Active
		}
	}
	return false
}

// m3: the seal's revision only grows across everything that invalidates a
// capability sealed to an installation: a revoke, a narrowing, an
// owner-aware withdrawal, an uninstall and a reinstall.
func TestTheSealRevisionNeverRepeats(t *testing.T) {
	h := newHarness(t)
	id := h.inst(acme, "a").ID
	last := uint64(0)
	step := func(what string) {
		t.Helper()
		seal, err := h.svc.Seals().Seal(h.ctx, "maya", id)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if seal.InstallationRevision <= last {
			t.Fatalf("%s: the seal revision is %d, was %d", what, seal.InstallationRevision, last)
		}
		last = seal.InstallationRevision
	}
	step("installed")
	h.grant("a", "viewer", "maya")
	h.revoke("a", "viewer", "maya", "")
	step("revoked")
	narrowed := solution("a", true)
	narrowed.Generation = 2
	narrowed.Roles["viewer"] = narrowed.Roles["viewer"][:1]
	if _, err := h.svc.ApplyModule(h.ctx, narrowed); err != nil {
		t.Fatal(err)
	}
	step("narrowed")
	blind := solution("a", false)
	blind.Generation = 3
	blind.Roles["viewer"] = narrowed.Roles["viewer"]
	if _, err := h.svc.ApplyModule(h.ctx, blind); err != nil {
		t.Fatal(err)
	}
	step("owner-aware withdrawn")
	if err := h.svc.Uninstall(h.ctx, nil, acme, id); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Seals().Seal(h.ctx, "maya", id); !errors.Is(err, workcontext.ErrNoSeal) {
		t.Fatalf("an uninstalled installation seals: %v", err)
	}
	h.install(acme, "a")
	step("reinstalled")
}

// m6: a module's principal is its own: never a person's, never an installed
// solution's, and never renamed by a later delivery.
func TestAModulePrincipalIsItsOwnForLife(t *testing.T) {
	h := newHarness(t)
	for name, m := range map[string]domain.Module{
		"a person's id":          {Name: "impostor", Principal: "maya", Kind: domain.KindModule, Generation: 1},
		"a solution's principal": {Name: "impostor", Principal: h.principal(acme, "a"), Kind: domain.KindModule, Generation: 1},
		"a renamed principal":    {Name: "store", Principal: "store-2", Kind: domain.KindModule, Generation: 2},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := h.svc.ApplyModule(h.ctx, m)
			code(t, err, domain.Denied)
		})
	}
}

// m7: the replay store is required; nothing defaults to memory.
func TestTheReplayStoreIsRequired(t *testing.T) {
	_, err := authority.New(memstore.New(), authority.Config{Issuer: "i", KeyID: "k", Signer: signerForTest(t), Keys: keys{}})
	if err == nil {
		t.Fatal("a service started with no replay store")
	}
}

// m2: a write whose fn fails leaves nothing behind.
func TestAFailedWriteLeavesNothing(t *testing.T) {
	store := memstore.New()
	store.PutOrganization(domain.Organization{ID: acme})
	boom := errors.New("boom")
	err := store.Write(h0, func(tx authority.Tx) error {
		if err := tx.PutInstallation(domain.Installation{ID: "i", Organization: acme, Target: "a", Status: domain.Active}); err != nil {
			return err
		}
		if err := tx.BumpAuthorizationRevision(acme); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	_ = store.Read(h0, func(tx authority.Tx) error {
		if _, err := tx.Installation("i"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("the failed write's installation survived: %v", err)
		}
		if rev, _ := tx.AuthorizationRevision(acme); rev != 1 {
			t.Fatalf("the failed write's revision survived: %d", rev)
		}
		return nil
	})
}

var h0 = context.Background()

func signerForTest(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return private
}
