package authority_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

func TestWithdrawnModuleCannotBeUninstalledByAPerson(t *testing.T) {
	h := newHarness(t)
	id := h.inst(acme, "store").ID
	if err := h.svc.WithdrawModule(h.ctx, "store"); err != nil {
		t.Fatal(err)
	}
	before := h.inst(acme, "store")
	refused(t, h.svc.Uninstall(h.ctx, h.admin(acme), acme, id), "never uninstalled")
	if after := h.inst(acme, "store"); !reflect.DeepEqual(after, before) {
		t.Fatalf("refusal mutated installation: %+v", after)
	}
}

func TestRolelessMemberGetsForeignAnswerFromEveryRoleCall(t *testing.T) {
	h := newHarness(t)
	for _, id := range []string{h.inst(acme, "a").ID, authority.StableInstallationID(acme, "absent")} {
		r := authority.RoleRequest{Organization: acme, InstallationID: id, Role: "viewer", PersonID: "maya"}
		_, grant := h.svc.GrantRole(h.ctx, h.person("remi"), r)
		_, revoke := h.svc.RevokeRole(h.ctx, h.person("remi"), r)
		_, list := h.svc.ListRoleGrants(h.ctx, h.person("remi"), acme, id)
		for name, err := range map[string]error{"grant": grant, "revoke": revoke, "list": list} {
			want := "installation " + id + " belongs to another organization than \"acme\""
			if err == nil || err.Error() != want {
				t.Errorf("%s: got %v, want %s", name, err, want)
			}
		}
	}
}

func TestMissingCallerCannotSelectHostPower(t *testing.T) {
	h := newHarness(t)
	before := h.inst(acme, "store")
	code(t, h.svc.Uninstall(h.ctx, authority.Person{}, acme, before.ID), domain.Denied)
	if !reflect.DeepEqual(h.inst(acme, "store"), before) {
		t.Fatal("empty caller retired module")
	}
	_, err := h.svc.Install(h.ctx, authority.Person{}, globex, "b", "author", h.admin(globex).ID, h.approval(globex, "b"), nil)
	code(t, err, domain.Denied)
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
		_, err := tx.Installation(authority.StableInstallationID(globex, "b"))
		if !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("empty caller installed solution: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The same trusted setup is available only through the explicit host methods.
	if err := h.svc.UninstallAsHost(h.ctx, acme, before.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.InstallAsHost(h.ctx, globex, "b", "author", h.admin(globex).ID, nil); err != nil {
		t.Fatal(err)
	}
}

type lifecycleOutage struct {
	authority.Store
	fail string
	err  error
}
type lifecycleOutageTx struct {
	authority.Tx
	fail string
	err  error
}

func (s lifecycleOutage) Write(ctx context.Context, fn func(authority.Tx) error) error {
	return s.Store.Write(ctx, func(tx authority.Tx) error { return fn(lifecycleOutageTx{tx, s.fail, s.err}) })
}
func (t lifecycleOutageTx) Person(id string) (domain.Person, error) {
	if t.fail == "person" {
		return domain.Person{}, t.err
	}
	return t.Tx.Person(id)
}
func (t lifecycleOutageTx) Member(org, id string) (domain.Person, error) {
	if t.fail == "person" {
		return domain.Person{}, t.err
	}
	return t.Tx.Member(org, id)
}
func (t lifecycleOutageTx) Installation(id string) (domain.Installation, error) {
	if t.fail == "installation" {
		return domain.Installation{}, t.err
	}
	return t.Tx.Installation(id)
}
func (t lifecycleOutageTx) ModuleNamed(name string) (domain.Module, error) {
	if t.fail == "module" {
		return domain.Module{}, t.err
	}
	return t.Tx.ModuleNamed(name)
}

func TestLifecycleStoreFailuresAreReturnedWithoutMutation(t *testing.T) {
	for _, fail := range []string{"person", "installation", "module"} {
		t.Run(fail, func(t *testing.T) {
			h := newHarness(t)
			outage := errors.New("store unavailable")
			svc, err := authority.New(lifecycleOutage{h.store, fail, outage}, h.cfg)
			if err != nil {
				t.Fatal(err)
			}
			before := h.inst(acme, "store")
			err = svc.Uninstall(h.ctx, h.admin(acme), acme, before.ID)
			if fail == "module" {
				// Uninstall never needs a manifest lookup to recognize a module.
				refused(t, err, "never uninstalled")
			} else if !errors.Is(err, outage) {
				t.Fatalf("uninstall hid outage: %v", err)
			}
			if !reflect.DeepEqual(h.inst(acme, "store"), before) {
				t.Fatal("outage mutated installation")
			}
			_, err = svc.Install(h.ctx, h.admin(globex), globex, "b", "author", h.admin(globex).ID, h.approval(globex, "b"), nil)
			if !errors.Is(err, outage) {
				t.Fatalf("install hid outage: %v", err)
			}
		})
	}
}
