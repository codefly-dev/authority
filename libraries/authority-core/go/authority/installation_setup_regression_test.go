package authority_test

import (
	"context"
	"errors"
	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	modulecontract "github.com/codefly-dev/core/contracts/module"
	"testing"
)

func TestReviewSetupUnrelatedBindingCannotBlockCurrentBinding(t *testing.T) {
	h := newHarness(t)
	destination := domain.Module{Name: "store", Principal: "store", Kind: domain.KindModule, Generation: 2, OwnerAware: true, ResourceKinds: authority.Scopes{sc(kind, "admin", "create", "read", "write")}, Methods: map[string]domain.MethodPolicy{setupMethod: {Requires: authority.Scopes{sc(kind, "create")}}}}
	if _, err := h.svc.ApplyModule(h.ctx, destination); err != nil {
		t.Fatal(err)
	}
	// Both destinations publish the same interface method. One has not adopted owner-aware enforcement.
	legacy := domain.Module{Name: "legacy-store", Principal: "legacy-store", Kind: domain.KindModule, Generation: 2, ResourceKinds: authority.Scopes{sc(legacyKind, "read")}, Methods: map[string]domain.MethodPolicy{setupMethod: {Requires: authority.Scopes{sc(legacyKind, "read")}}}}
	if _, err := h.svc.ApplyModule(h.ctx, legacy); err != nil {
		t.Fatal(err)
	}
	m := solution("b", true)
	m.Generation = 2
	m.InstallationRole = domain.NoInstallationRole
	m.Setup = []modulecontract.ResolvedSetup{{Binding: "legacy", Methods: []string{setupMethod}, Scopes: []string{legacyKind + ":read"}}, {Binding: "store", Methods: []string{setupMethod}, Scopes: []string{kind + ":create"}}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	approval := h.approval(globex, "b")
	admin := h.admin(globex)
	inst, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, func(context.Context, domain.Installation) error { return awaitingStep })
	if !errors.Is(err, awaitingStep) {
		t.Fatal(err)
	}
	a := authority.InstallationStepAttempt{InstallationID: inst.ID, Organization: inst.Organization, Target: inst.Target, TargetID: approval.TargetID, Revision: inst.Revision, Generation: approval.Generation, Consent: inst.Consent, Digest: approval.Digest}
	step := issueStep(t, h, a)
	issued, err := h.svc.IssueForInstallationSetup(h.ctx, authority.Workload{Module: "b"}, step.Token, setupMethod, authority.IssueRequest{Binding: "store"})
	if err != nil {
		t.Fatalf("independent current binding failed to issue: %v", err)
	}
	if _, _, _, err = h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err != nil {
		t.Fatalf("issued current binding failed verification because another binding is ineligible: %v", err)
	}
}

func TestReviewSetupMustStayBoundToAuthenticatedCallbackAttempt(t *testing.T) {
	for at := 1; at <= 30; at++ {
		t.Run(string(rune('A'+at-1)), func(t *testing.T) {
			h, a, _ := pendingSetup(t)
			step := issueStep(t, h, a)
			changed := false
			store := &stepRaceStore{Store: h.store, at: at, change: func() {
				changed = true
				approval := h.approval(globex, "b")
				admin := h.admin(globex)
				_, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, func(context.Context, domain.Installation) error { return awaitingStep })
				if !errors.Is(err, awaitingStep) {
					t.Fatal(err)
				}
			}}
			svc, err := authority.New(store, h.cfg)
			if err != nil {
				t.Fatal(err)
			}
			issued, err := svc.IssueForInstallationSetup(h.ctx, authority.Workload{Module: "b"}, step.Token, setupMethod, authority.IssueRequest{Binding: "store"})
			if changed && err == nil {
				if _, _, err := h.svc.VerifyInstallationStep(h.ctx, step.Token, "b"); err == nil {
					t.Fatal("probe did not obsolete callback")
				}
				if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false); err == nil {
					t.Fatalf("read boundary %d: stale callback minted valid capability for replacement consent; old rev=%d, new rev=%d", at, a.Revision, issued.Context.GetSeal().GetInstallationRevision())
				}
			}
		})
	}
}

type eleganceReadFailure struct {
	authority.Store
	at, reads int
	failure   error
}

func (s *eleganceReadFailure) Read(ctx context.Context, f func(authority.Tx) error) error {
	s.reads++
	if s.reads == s.at {
		return s.failure
	}
	return s.Store.Read(ctx, f)
}
func TestEleganceSetupCheckInfrastructureErrorClassification(t *testing.T) {
	for at := 1; at <= 20; at++ {
		h, attempt, _ := pendingSetup(t)
		step := issueStep(t, h, attempt)
		issued, err := h.svc.IssueForInstallationSetup(h.ctx, authority.Workload{Module: "b"}, step.Token, setupMethod, authority.IssueRequest{Binding: "store"})
		if err != nil {
			t.Fatal(err)
		}
		failure := errors.New("test backing store unavailable")
		store := &eleganceReadFailure{Store: h.store, at: at, failure: failure}
		svc, err := authority.New(store, h.cfg)
		if err != nil {
			t.Fatal(err)
		}
		store.reads = 0
		_, _, _, err = svc.CheckMethod(h.ctx, issued.Token, "store", setupMethod, false)
		if store.reads >= at && !errors.Is(err, failure) {
			t.Fatalf("store read %d: lost operational failure: %v", at, err)
		}
	}
}
