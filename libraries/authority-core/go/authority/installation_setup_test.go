package authority_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	modulecontract "github.com/codefly-dev/core/contracts/module"
)

const setupMethod = "/store.v1.Store/Define"
const otherSetupMethod = "/store.v1.Store/Project"

func pendingSetup(t *testing.T) (*harness, authority.InstallationStepAttempt, *domain.ConsentApproval) {
	t.Helper()
	h := newHarness(t)
	destination := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 2,
		OwnerAwareResourceKinds: []string{kind}, ResourceKinds: authority.Scopes{sc(kind, "admin", "create", "read", "write")},
		Methods: map[string]domain.MethodPolicy{setupMethod: {Requires: authority.Scopes{sc(kind, "create")}}, otherSetupMethod: {Requires: authority.Scopes{sc(kind, "create")}}}}
	if _, err := h.svc.ApplyModule(h.ctx, destination); err != nil {
		t.Fatal(err)
	}
	m := solution("b", true)
	m.Generation = 2
	m.InstallationRole = domain.NoInstallationRole
	m.Setup = []modulecontract.ResolvedSetup{{Binding: "store", Methods: []string{setupMethod}, Scopes: []string{kind + ":create"}}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	approval := h.approval(globex, "b")
	admin := h.admin(globex)
	inst, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, func(context.Context, domain.Installation) error { return awaitingStep })
	if !errors.Is(err, awaitingStep) || inst.Status != domain.Pending {
		t.Fatalf("pending: %+v %v", inst, err)
	}
	return h, authority.InstallationStepAttempt{InstallationID: inst.ID, Organization: inst.Organization, Target: inst.Target, TargetID: approval.TargetID,
		Revision: inst.Revision, Generation: approval.Generation, Consent: inst.Consent, Digest: approval.Digest}, approval
}

func TestSetupGrantIsExactOwnedTemporaryAndNotStanding(t *testing.T) {
	h, a, approval := pendingSetup(t)
	step := issueStep(t, h, a)
	issue := func(r authority.IssueRequest, method string, actor string) (authority.Issued, error) {
		return h.svc.IssueForInstallationSetup(h.ctx, authority.Workload{Module: actor}, step.Token, method, r)
	}
	r := authority.IssueRequest{Binding: "store", TTL: time.Hour}
	issued, err := issue(r, setupMethod, "b")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Context.GetExpiresAtUnix() > step.Context.GetExpiresAtUnix() {
		t.Fatal("outlived callback")
	}
	if got := issued.Context.GetAuthorityScopes(); len(got) != 1 || got[0].GetResourceOwnerId() != h.principal(globex, "b") {
		t.Fatalf("not installation confined: %v", got)
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"", otherSetupMethod, authority.InstallationStepRPCMethod} {
		if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", method, true); err == nil {
			t.Fatalf("admitted %q", method)
		}
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, step.Token, "store", setupMethod, false); err == nil {
		t.Fatal("callback became data authority")
	}
	if _, err := h.svc.Verify(h.ctx, issued.Token, "store"); err == nil {
		t.Fatal("ordinary verify accepted setup")
	}
	if _, err := h.svc.IssueChild(h.ctx, issued.Token, authority.Workload{Module: "store"}, authority.IssueRequest{Binding: "self", Audience: "store"}); err == nil {
		t.Fatal("setup fanout accepted")
	}
	for name, req := range map[string]authority.IssueRequest{
		"foreign org": {Binding: "store", Organization: acme}, "foreign audience": {Binding: "store", Audience: "legacy-store"},
		"foreign binding": {Binding: "legacy"}, "ordinary operation": {Binding: "store", Operation: "invoke"},
		"foreign owner": {Binding: "store", Scopes: authority.Scopes{owned(kind, "other", []string{"create"})}},
		"wrong action":  {Binding: "store", Scopes: authority.Scopes{sc(kind, "read")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issue(req, setupMethod, "b"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := issue(r, otherSetupMethod, "b"); err == nil {
		t.Fatal("undeclared equal-scope method accepted")
	}
	if _, err := issue(r, setupMethod, "a"); err == nil {
		t.Fatal("wrong workload accepted")
	}
	h.now = time.Unix(issued.Context.GetExpiresAtUnix(), 0)
	if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err == nil {
		t.Fatal("exact expiry accepted")
	}
	h.now = h.now.Add(-time.Second)
	admin := h.admin(globex)
	if _, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, func(context.Context, domain.Installation) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err == nil {
		t.Fatal("setup survives activation")
	}
	if _, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "b"}, a.InstallationID, authority.IssueRequest{Binding: "store"}); err == nil {
		t.Fatal("setup created standing grant")
	}
}

// Capability withdrawal is permanent for the old evidence, even when the
// destination later restores the same owner-aware declaration.
func TestSetupOwnerCapabilityWithdrawalCannotReviveOldEvidence(t *testing.T) {
	h, a, _ := pendingSetup(t)
	step := issueStep(t, h, a)
	issued, err := h.svc.IssueForInstallationSetup(h.ctx, authority.Workload{Module: "b"}, step.Token, setupMethod, authority.IssueRequest{Binding: "store"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "legacy-store", setupMethod, false); err == nil {
		t.Fatal("wrong audience accepted")
	}
	destination := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 3,
		ResourceKinds: authority.Scopes{sc(kind, "admin", "create", "read", "write")},
		Methods:       map[string]domain.MethodPolicy{setupMethod: {Requires: authority.Scopes{sc(kind, "create")}}, otherSetupMethod: {Requires: authority.Scopes{sc(kind, "create")}}}}
	if _, err := h.svc.ApplyModule(h.ctx, destination); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err == nil {
		t.Fatal("withdrawn owner capability accepted")
	}
	destination.Generation++
	destination.OwnerAwareResourceKinds = []string{kind}
	if _, err := h.svc.ApplyModule(h.ctx, destination); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err == nil {
		t.Fatal("restored capability revived old evidence")
	}
}
