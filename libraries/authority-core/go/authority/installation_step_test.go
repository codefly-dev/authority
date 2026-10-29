package authority_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

var awaitingStep = errors.New("setup not acknowledged")

func pendingStep(t *testing.T) (*harness, authority.InstallationStepAttempt, *domain.ConsentApproval) {
	t.Helper()
	h := newHarness(t)
	approval := h.approval(globex, "b")
	admin := h.admin(globex)
	inst, err := h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, approval, func(context.Context, domain.Installation) error { return awaitingStep })
	if !errors.Is(err, awaitingStep) || inst.Status != domain.Pending {
		t.Fatalf("pending: %+v %v", inst, err)
	}
	return h, authority.InstallationStepAttempt{InstallationID: inst.ID, Organization: inst.Organization, Target: inst.Target, TargetID: approval.TargetID, Revision: inst.Revision, Generation: approval.Generation, Consent: inst.Consent, Digest: approval.Digest}, approval
}
func issueStep(t *testing.T, h *harness, a authority.InstallationStepAttempt) authority.Issued {
	t.Helper()
	issued, err := h.svc.IssueInstallationStep(h.ctx, a, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}
func TestInstallationStepOnlyAdmitsExactSetupMethods(t *testing.T) {
	h, a, approval := pendingStep(t)
	issued := issueStep(t, h, a)
	wc := issued.Context
	if wc.GetSeal().GetInstallationRevision() != a.Revision || wc.GetOrganizationId() != a.Organization || len(wc.GetAuthorityScopes()) != 1 || wc.GetAuthorityScopes()[0].GetResourceKind() != "installations" {
		t.Fatalf("wrong setup claims: %v", wc)
	}
	for _, method := range []string{authority.InstallationStepHTTPMethod, authority.InstallationStepRPCMethod} {
		for _, advisory := range []bool{false, true} {
			v, _, refusal, err := h.svc.CheckMethod(h.ctx, issued.Token, a.TargetID, method, advisory)
			if err != nil || refusal != nil || v == nil {
				t.Fatalf("%s: %v %v", method, refusal, err)
			}
		}
	}
	for _, method := range []string{"", "GET /_codefly/installations", "POST /_codefly/installations/", "POST /other"} {
		if _, _, _, err := h.svc.CheckMethod(h.ctx, issued.Token, a.TargetID, method, true); err == nil {
			t.Fatalf("admitted %q", method)
		}
	}
	if _, err := h.svc.Verify(h.ctx, issued.Token, a.TargetID); err == nil {
		t.Fatal("ordinary verify accepted")
	}
	if _, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: a.Target}, a.InstallationID, authority.IssueRequest{Audience: a.TargetID}); err == nil {
		t.Fatal("ordinary pending issue accepted")
	}
	if _, _, err := h.svc.VerifyInstallationStep(h.ctx, issued.Token, "a"); err == nil {
		t.Fatal("wrong receiver accepted")
	}
	if _, _, err := h.svc.VerifyInstallationStep(h.ctx, issued.Token+"x", a.TargetID); err == nil {
		t.Fatal("tampered token accepted")
	}
	admin := h.admin(globex)
	inst, err := h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, approval, func(context.Context, domain.Installation) error { return nil })
	if err != nil || inst.Status != domain.Active {
		t.Fatalf("ack: %+v %v", inst, err)
	}
	if _, _, err := h.svc.VerifyInstallationStep(h.ctx, issued.Token, a.TargetID); err == nil {
		t.Fatal("active setup token accepted")
	}
	if _, err := h.svc.Verify(h.ctx, issued.Token, a.TargetID); err == nil {
		t.Fatal("activation converted setup token into ordinary authority")
	}
	err = h.store.Read(h.ctx, func(tx authority.Tx) error {
		grants, e := tx.RoleGrants(a.InstallationID)
		if len(grants) != 0 {
			t.Fatal("automatic grants", grants)
		}
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestInstallationStepRejectsEveryChangedAttemptField(t *testing.T) {
	cases := map[string]func(*authority.InstallationStepAttempt){
		"id":               func(a *authority.InstallationStepAttempt) { a.InstallationID = "missing" },
		"organization":     func(a *authority.InstallationStepAttempt) { a.Organization = acme },
		"target":           func(a *authority.InstallationStepAttempt) { a.Target = "a" },
		"principal":        func(a *authority.InstallationStepAttempt) { a.TargetID = "a" },
		"revision":         func(a *authority.InstallationStepAttempt) { a.Revision++ },
		"generation":       func(a *authority.InstallationStepAttempt) { a.Generation++ },
		"digest":           func(a *authority.InstallationStepAttempt) { a.Digest = "other" },
		"operation":        func(a *authority.InstallationStepAttempt) { a.Consent.OperationID = "other" },
		"intent":           func(a *authority.InstallationStepAttempt) { a.Consent.Intent = "other" },
		"receipt revision": func(a *authority.InstallationStepAttempt) { a.Consent.Revision++ },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			h, a, _ := pendingStep(t)
			change(&a)
			if got, err := h.svc.IssueInstallationStep(h.ctx, a, time.Minute); err == nil || got.Token != "" {
				t.Fatal("changed attempt issued", err)
			}
		})
	}
}
func TestInstallationStepRevocationAndReplacement(t *testing.T) {
	for _, change := range []string{"uninstall", "approval", "delivery", "authorization", "receipt", "activation"} {
		t.Run(change, func(t *testing.T) {
			h, a, approval := pendingStep(t)
			issued := issueStep(t, h, a)
			admin := h.admin(globex)
			var err error
			switch change {
			case "uninstall":
				err = h.svc.Uninstall(h.ctx, admin, globex, a.InstallationID)
			case "approval":
				_, err = h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, h.approval(globex, "b"), func(context.Context, domain.Installation) error { return awaitingStep })
				if errors.Is(err, awaitingStep) {
					err = nil
				}
			case "delivery":
				m := solution("b", false)
				m.Generation++
				_, err = h.svc.ApplyModule(h.ctx, m)
			case "authorization":
				err = h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.BumpAuthorizationRevision(globex) })
			case "receipt":
				err = h.store.Write(h.ctx, func(tx authority.Tx) error {
					i, e := tx.Installation(a.InstallationID)
					if e != nil {
						return e
					}
					i.Consent = domain.ConsentReceipt{}
					return tx.PutInstallation(i)
				})
			case "activation":
				_, err = h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, approval, func(context.Context, domain.Installation) error { return nil })
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = h.svc.VerifyInstallationStep(h.ctx, issued.Token, a.TargetID); err == nil {
				t.Fatal("stale step verified")
			}
			if change != "authorization" {
				if _, err = h.svc.IssueInstallationStep(h.ctx, a, time.Minute); err == nil {
					t.Fatal("stale attempt issued")
				}
			}
		})
	}
}
func TestInstallationStepLeaseBoundAndExactExpiry(t *testing.T) {
	h, a, _ := pendingStep(t)
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := h.svc.IssueInstallationStep(h.ctx, a, ttl); err == nil {
			t.Fatal("nonpositive lease accepted")
		}
	}
	issued, err := h.svc.IssueInstallationStep(h.ctx, a, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Context.GetExpiresAtUnix()-h.now.Unix() != 60 {
		t.Fatal("TTL not capped")
	}
	h.now = h.now.Add(60 * time.Second)
	if _, _, err := h.svc.VerifyInstallationStep(h.ctx, issued.Token, a.TargetID); err == nil {
		t.Fatal("Core clock skew extended setup lease")
	}
	fresh := issueStep(t, h, a)
	if _, _, err := h.svc.VerifyInstallationStep(h.ctx, fresh.Token, a.TargetID); err != nil {
		t.Fatal("pending retry failed", err)
	}
}

// Deterministic state changes after a read exercise the decision/mint/verify
// window. The final successful read is admission, not a reservation through I/O.
type stepRaceStore struct {
	authority.Store
	at, reads int
	change    func()
}

func (s *stepRaceStore) Read(ctx context.Context, fn func(authority.Tx) error) error {
	err := s.Store.Read(ctx, fn)
	s.reads++
	if s.reads == s.at {
		s.change()
	}
	return err
}
func TestInstallationStepFencesEveryReadBoundary(t *testing.T) {
	for _, verify := range []bool{false, true} {
		for at := 1; at <= 8; at++ {
			t.Run(fmt.Sprintf("verify=%v/read=%d", verify, at), func(t *testing.T) {
				h, a, _ := pendingStep(t)
				issued := issueStep(t, h, a)
				changed := false
				store := &stepRaceStore{Store: h.store, at: at, change: func() {
					changed = true
					if err := h.svc.Uninstall(h.ctx, h.admin(globex), globex, a.InstallationID); err != nil {
						t.Fatal(err)
					}
				}}
				svc, err := authority.New(store, h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				if verify {
					_, _, err = svc.VerifyInstallationStep(h.ctx, issued.Token, a.TargetID)
				} else {
					_, err = svc.IssueInstallationStep(h.ctx, a, time.Minute)
				}
				if changed && store.reads > at && err == nil {
					t.Fatal("state changed before final admission")
				}
			})
		}
	}
}
func TestInstallationStepNormalActiveTokenCannotSetup(t *testing.T) {
	h := newHarness(t)
	inst := h.install(globex, "b")
	token, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "b"}, inst.ID, authority.IssueRequest{Audience: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.svc.CheckMethod(h.ctx, token.Token, "b", authority.InstallationStepHTTPMethod, true); err == nil {
		t.Fatal("ordinary token admitted setup")
	}
}

func TestInstallationStepAuthenticatesBeforeStateReads(t *testing.T) {
	h, a, _ := pendingStep(t)
	store := &stepRaceStore{Store: h.store, at: 100, change: func() {}}
	svc, err := authority.New(store, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.VerifyInstallationStep(h.ctx, "invalid", a.TargetID); err == nil {
		t.Fatal("invalid token admitted")
	}
	if store.reads != 0 {
		t.Fatal("unauthenticated state read")
	}
}
func TestInstallationStepClockDelayCannotExtendLease(t *testing.T) {
	for _, verify := range []bool{false, true} {
		for _, delay := range []time.Duration{100 * time.Millisecond, 31 * time.Second} {
			t.Run(fmt.Sprintf("verify=%v/delay=%s", verify, delay), func(t *testing.T) {
				h, a, _ := pendingStep(t)
				h.now = h.now.Add(950 * time.Millisecond)
				started := h.now
				issued := issueStep(t, h, a)
				store := &stepRaceStore{Store: h.store, at: 2, change: func() { h.now = h.now.Add(delay) }}
				svc, err := authority.New(store, h.cfg)
				if err != nil {
					t.Fatal(err)
				}
				if verify {
					_, _, err = svc.VerifyInstallationStep(h.ctx, issued.Token, a.TargetID)
				} else {
					issued, err = svc.IssueInstallationStep(h.ctx, a, 30*time.Second)
				}
				if delay >= 30*time.Second {
					if err == nil {
						t.Fatal("expired lease admitted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if issued.Context.GetExpiresAtUnix() != started.Add(30*time.Second).Unix() {
					t.Fatal("lease extended by state latency")
				}
			})
		}
	}
}
