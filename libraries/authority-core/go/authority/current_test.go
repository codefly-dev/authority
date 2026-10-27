package authority_test

import (
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

func TestCurrentInstallationIsConfinedToTheAuthenticatedAudience(t *testing.T) {
	h := newHarness(t)
	parent := h.must(h.root("rob", "store", sc(kind, "read")))
	inst, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: "store"})
	if err != nil || inst.ID != authority.StableInstallationID(acme, "store") || inst.Organization != acme || inst.Target != "store" {
		t.Fatalf("current installation: %+v %v", inst, err)
	}
	for _, actor := range []string{"legacy-store", "a", "missing", ""} {
		if _, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: actor}); err == nil {
			t.Fatalf("foreign workload %q read an installation", actor)
		}
	}
	if _, err := h.svc.CurrentInstallation(h.ctx, "forged", authority.Workload{Module: "store"}); err == nil {
		t.Fatal("forged parent read an installation")
	}
	h.store.PutPerson(domain.Person{ID: "omar", Organization: globex, Roles: []string{"store-reader"}})
	h.store.PutOrgRole(domain.OrgRole{Organization: globex, Name: "store-reader", Scopes: []domain.RoleScope{{Kind: kind, Actions: []string{"read"}, Resources: []resources.Grant{{ID: "store-x"}}}}})
	foreign := h.must(h.root("omar", "store", sc(kind, "read")))
	other, err := h.svc.CurrentInstallation(h.ctx, foreign.Token, authority.Workload{Module: "store"})
	if err != nil || other.Organization != globex || other.ID == inst.ID {
		t.Fatalf("tenant isolation: %+v %v", other, err)
	}
}

func TestCurrentInstallationRechecksRevokedAuthority(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	parent := h.must(h.root("maya", "a"))
	if _, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: "a"}); err != nil {
		t.Fatal(err)
	}
	h.revoke("a", "viewer", "maya", "")
	if _, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: "a"}); err == nil {
		t.Fatal("revoked parent still read installation metadata")
	}
}

func TestCurrentInstallationForAChildIsTheDestinationNotTheSource(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	child := h.must(h.through("maya", "a", "store"))
	if child.Context.GetSeal().GetInstallationId() != h.inst(acme, "a").ID {
		t.Fatal("fixture must carry a source-actor seal")
	}
	got, err := h.svc.CurrentInstallation(h.ctx, child.Token, authority.Workload{Module: "store"})
	if err != nil || got.ID != authority.StableInstallationID(acme, "store") {
		t.Fatalf("destination installation: %+v %v", got, err)
	}
}
