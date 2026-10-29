package authority_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

func declaration(t *testing.T, h *harness, selector string) domain.Module {
	t.Helper()
	m := solution("b", true)
	m.Generation++
	m.InstallationRole = selector
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallationDeclarationSelection(t *testing.T) {
	for _, tc := range []struct {
		name, selector, requested, want string
		refused                         bool
	}{
		{"legacy", "", "author", "author", false},
		{"legacy missing", "", "", "", true},
		{"legacy caller none", "", "none", "", true},
		{"named default", "editor", "", "editor", false},
		{"named same", "editor", "editor", "editor", false},
		{"named override", "editor", "author", "", true},
		{"named missing", "missing", "", "", true},
		{"declared none", "none", "", "none", false},
		{"none caller none", "none", "none", "", true},
		{"none override", "none", "author", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			declaration(t, h, tc.selector)
			admin := h.admin(globex)
			calls := 0
			inst, err := h.svc.Install(h.ctx, admin, globex, "b", tc.requested, admin.ID, h.approval(globex, "b"), func(context.Context, domain.Installation) error { calls++; return nil })
			if tc.refused {
				if err == nil || calls != 0 {
					t.Fatalf("accepted refused selection: %+v %v, setup calls %d", inst, err, calls)
				}
				return
			}
			if err != nil || inst.Status != domain.Active || inst.AgentRole != tc.want || calls != 1 {
				t.Fatalf("selection: %+v %v", inst, err)
			}
		})
	}
}

func TestNoStandingAuthorityStillHasFencedSetup(t *testing.T) {
	h := newHarness(t)
	m := declaration(t, h, "none")
	if _, exists := m.Roles["none"]; exists {
		t.Fatal("fixture contains a synthetic role")
	}
	admin := h.admin(globex)
	approval := h.approval(globex, "b")
	inst, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, func(context.Context, domain.Installation) error { return awaitingStep })
	if !errors.Is(err, awaitingStep) || inst.AgentRole != "none" || inst.Status != domain.Pending {
		t.Fatalf("pending: %+v %v", inst, err)
	}
	attempt := authority.InstallationStepAttempt{InstallationID: inst.ID, Organization: globex, Target: "b", TargetID: approval.TargetID, Revision: inst.Revision, Generation: approval.Generation, Consent: inst.Consent, Digest: approval.Digest}
	issued := issueStep(t, h, attempt)
	if _, _, err = h.svc.VerifyInstallationStep(h.ctx, issued.Token, approval.TargetID); err != nil {
		t.Fatal(err)
	}
	active, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, func(context.Context, domain.Installation) error { return nil })
	if err != nil || active.Status != domain.Active || active.PrincipalID != inst.PrincipalID || active.Consent != inst.Consent {
		t.Fatalf("resume: %+v %v", active, err)
	}
	if _, _, err = h.svc.VerifyInstallationStep(h.ctx, issued.Token, approval.TargetID); err == nil {
		t.Fatal("setup survived activation")
	}
	for _, req := range []authority.IssueRequest{{Audience: "b"}, {Audience: "b", Scopes: m.Roles["author"]}} {
		if out, err := h.svc.IssueForInstallation(h.ctx, authority.Workload{Module: "b"}, inst.ID, req); err == nil || out.Token != "" {
			t.Fatal("zero standing authority issued", err)
		}
	}
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
		grants, err := tx.RoleGrants(inst.ID)
		if len(grants) != 0 {
			t.Fatal("automatic grants", grants)
		}
		current, err2 := tx.ModuleNamed("b")
		if _, exists := current.Roles["none"]; exists {
			t.Fatal("synthetic role created")
		}
		if err != nil {
			return err
		}
		return err2
	}); err != nil {
		t.Fatal(err)
	}
	// People continue to need a separate grant, including the installer.
	if out, err := h.svc.IssueForPerson(h.ctx, admin, authority.IssueRequest{Audience: "b"}); err == nil || out.Token != "" {
		t.Fatal("installer gained solution authority", err)
	}
}

func TestInstallationDeclarationDoesNotRelaxRoles(t *testing.T) {
	for _, fault := range []string{"empty role", "missing installer"} {
		t.Run(fault, func(t *testing.T) {
			h := newHarness(t)
			m := solution("b", true)
			m.Generation++
			m.InstallationRole = "none"
			if fault == "empty role" {
				m.Roles["editor"] = nil
			} else {
				delete(m.Roles, domain.InstallerRole)
			}
			if _, err := h.svc.ApplyModule(h.ctx, m); err == nil {
				t.Fatal("role rule relaxed")
			}
		})
	}
}

func TestInstallationDeclarationDigestAndStaleApproval(t *testing.T) {
	for _, field := range []string{"selector", "edges"} {
		t.Run(field, func(t *testing.T) {
			h := newHarness(t)
			approval := h.approval(globex, "b")
			err := h.store.Write(h.ctx, func(tx authority.Tx) error {
				m, err := tx.ModuleNamed("b")
				if err != nil {
					return err
				}
				if field == "selector" {
					m.InstallationRole = "author"
				} else {
					m.EdgeDependencies = []domain.EdgeDependency{{Module: "catalogue-id", Presence: "required"}}
				}
				return tx.PutModule(m)
			})
			if err != nil {
				t.Fatal(err)
			}
			admin := h.admin(globex)
			_, err = h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, approval, nil)
			if err == nil || !strings.Contains(err.Error(), "DIGEST_CHANGED") {
				t.Fatal("changed declaration reused review", err)
			}
		})
	}
}

func TestInstallationDeclarationLegacyDigestBytes(t *testing.T) {
	// Captured field order/representation from Module at parent 940ddd642b55.
	const legacy = `{"Name":"legacy","Principal":"principal","Kind":"solution","Generation":1,"StandIn":false,"ResourceKinds":null,"Bindings":null,"Roles":null,"OwnedRoles":null,"OwnerAware":false,"Methods":null}`
	m := domain.Module{Name: "legacy", Principal: "principal", Kind: domain.KindSolution, Generation: 1}
	for _, edges := range [][]domain.EdgeDependency{nil, {}} {
		m.EdgeDependencies = edges
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != legacy {
			t.Fatalf("legacy JSON changed: %s", raw)
		}
	}
	h := newHarness(t)
	var mStored domain.Module
	if err := h.store.Read(h.ctx, func(tx authority.Tx) error { var err error; mStored, err = tx.ModuleNamed("b"); return err }); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(mStored)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	if got := h.approval(globex, "b").Digest; got != want {
		t.Fatalf("digest %s != %s", got, want)
	}
}

func TestNamedInstallationDeclarationRetryPreservesOriginalRequest(t *testing.T) {
	h := newHarness(t)
	declaration(t, h, "editor")
	admin := h.admin(globex)
	approval := h.approval(globex, "b")
	step := func(context.Context, domain.Installation) error { return awaitingStep }
	first, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, step)
	if !errors.Is(err, awaitingStep) {
		t.Fatal(err)
	}
	// Equal effective authority does not make two different requests the same
	// reviewed operation. Retain the original empty request on retries.
	_, err = h.svc.Install(h.ctx, admin, globex, "b", "editor", admin.ID, approval, step)
	refused(t, err, "INSTALLATION_APPROVAL_OPERATION_CONFLICT")
	again, err := h.svc.Install(h.ctx, admin, globex, "b", "", admin.ID, approval, step)
	if !errors.Is(err, awaitingStep) || again.Consent != first.Consent || again.AgentRole != "editor" {
		t.Fatalf("retry: %+v %v", again, err)
	}
}

func TestInstallationDeclarationStoreSnapshotsDoNotAlias(t *testing.T) {
	h := newHarness(t)
	m := solution("b", true)
	m.Generation++
	m.InstallationRole = "none"
	m.EdgeDependencies = []domain.EdgeDependency{{Module: "catalogue-id", Presence: "required"}}
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	m.EdgeDependencies[0].Module = "mutated caller"
	offer, err := h.svc.ReviewOffer(h.ctx, h.admin(globex), globex, "b")
	if err != nil {
		t.Fatal(err)
	}
	if offer.Module.EdgeDependencies[0].Module != "catalogue-id" {
		t.Fatal("store aliases input")
	}
	offer.Module.EdgeDependencies[0].Module = "mutated review"
	again, err := h.svc.ReviewOffer(h.ctx, h.admin(globex), globex, "b")
	if err != nil {
		t.Fatal(err)
	}
	if again.Module.EdgeDependencies[0].Module != "catalogue-id" || again.Approval.Digest != offer.Approval.Digest {
		t.Fatal("store aliases output")
	}
}
