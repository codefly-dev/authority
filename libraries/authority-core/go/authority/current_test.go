package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

func TestCurrentInstallationIsConfinedToTheAuthenticatedAudience(t *testing.T) {
	h := newHarness(t)
	// rob at acme and omar at globex are users of the ledger's page: each
	// holds its role on their own organisation's installation.
	ledgerWithRoles(t, h, "rob")
	parent := h.must(h.root("rob", "ledger", owned(ledgerKind, "", []string{"read"}, "entry-x")))
	inst, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: "ledger"})
	if err != nil || inst.ID != authority.StableInstallationID(acme, "ledger") || inst.Organization != acme || inst.Target != "ledger" {
		t.Fatalf("current installation: %+v %v", inst, err)
	}
	for _, actor := range []string{"legacy-store", "store", "a", "missing", ""} {
		if _, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: actor}); err == nil {
			t.Fatalf("foreign workload %q read an installation", actor)
		}
	}
	if _, err := h.svc.CurrentInstallation(h.ctx, "forged", authority.Workload{Module: "ledger"}); err == nil {
		t.Fatal("forged parent read an installation")
	}
	if _, err := h.svc.GrantRole(h.ctx, h.person("zoe"), authority.RoleRequest{Organization: globex, InstallationID: h.inst(globex, "ledger").ID, Role: domain.UserRole, PersonID: "omar"}); err != nil {
		t.Fatal(err)
	}
	foreign := h.must(h.root("omar", "ledger", owned(ledgerKind, "", []string{"read"}, "entry-x")))
	other, err := h.svc.CurrentInstallation(h.ctx, foreign.Token, authority.Workload{Module: "ledger"})
	if err != nil || other.Organization != globex || other.ID == inst.ID {
		t.Fatalf("tenant isolation: %+v %v", other, err)
	}
}

func TestCurrentInstallationRechecksRevokedAuthority(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "user", "maya")
	parent := h.must(h.root("maya", "a"))
	if _, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: "a"}); err != nil {
		t.Fatal(err)
	}
	h.revoke("a", "user", "maya", "")
	if _, err := h.svc.CurrentInstallation(h.ctx, parent.Token, authority.Workload{Module: "a"}); err == nil {
		t.Fatal("revoked parent still read installation metadata")
	}
}

func TestCurrentInstallationForAChildIsTheDestinationNotTheSource(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "user", "maya")
	child := h.must(h.through("maya", "a", "store"))
	if child.Context.GetSeal().GetInstallationId() != h.inst(acme, "a").ID {
		t.Fatal("fixture must carry a source-actor seal")
	}
	got, err := h.svc.CurrentInstallation(h.ctx, child.Token, authority.Workload{Module: "store"})
	if err != nil || got.ID != authority.StableInstallationID(acme, "store") {
		t.Fatalf("destination installation: %+v %v", got, err)
	}
}
