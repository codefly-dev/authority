package authority_test

import (
	"context"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

func TestInstallationConsentBindsReviewedStateAndOperation(t *testing.T) {
	h := newHarness(t)
	admin := h.admin(globex)
	a := h.approval(globex, "b")
	steps := 0
	step := func(context.Context, domain.Installation) error { steps++; return nil }
	install := func(a *domain.ConsentApproval, role string) (domain.Installation, error) {
		return h.svc.Install(h.ctx, admin, globex, "b", role, admin.ID, a, step)
	}
	_, err := install(nil, "author")
	refused(t, err, "INSTALLATION_APPROVAL_REQUIRED")
	for _, mutate := range []struct {
		reason string
		change func(*domain.ConsentApproval)
	}{
		{"GENERATION_CHANGED", func(a *domain.ConsentApproval) { a.Generation++ }},
		{"GENERATION_CHANGED", func(a *domain.ConsentApproval) { a.TargetID = "another-target" }},
		{"DIGEST_CHANGED", func(a *domain.ConsentApproval) { a.Digest = "sha256:unreviewed" }},
		{"REVISION_CHANGED", func(a *domain.ConsentApproval) { a.ExpectedRevision++ }},
	} {
		bad := *a
		mutate.change(&bad)
		_, err := install(&bad, "author")
		refused(t, err, "INSTALLATION_APPROVAL_"+mutate.reason)
	}
	if steps != 0 {
		t.Fatal("a refused approval ran the install step")
	}
	first, err := install(a, "author")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := install(a, "author")
	if err != nil || first != retry || steps != 1 {
		t.Fatalf("unchanged retry: %+v, steps=%d, err=%v", retry, steps, err)
	}
	_, err = install(a, "viewer")
	refused(t, err, "INSTALLATION_APPROVAL_OPERATION_CONFLICT")
	_, err = h.svc.Install(h.ctx, admin, globex, "b", "author", "", a, step)
	refused(t, err, "INSTALLATION_APPROVAL_OPERATION_CONFLICT")
	if err := h.svc.Uninstall(h.ctx, admin, globex, first.ID); err != nil {
		t.Fatal(err)
	}
	_, err = install(a, "author")
	refused(t, err, "INSTALLATION_APPROVAL_REVISION_CHANGED")
	fresh := h.approval(globex, "b")
	again, err := install(fresh, "author")
	if err != nil || again.PrincipalID != first.PrincipalID || again.Revision <= first.Revision {
		t.Fatalf("fresh reinstall: %+v %v", again, err)
	}
	m := solution("b", false)
	m.Generation++
	if _, err := h.svc.ApplyModule(h.ctx, m); err != nil {
		t.Fatal(err)
	}
	_, err = install(fresh, "author")
	refused(t, err, "INSTALLATION_APPROVAL_GENERATION_CHANGED")
}

func TestInstallationConsentIsRecheckedAtAcknowledgement(t *testing.T) {
	for _, change := range []string{"delivery", "revocation", "administrator"} {
		t.Run(change, func(t *testing.T) {
			h := newHarness(t)
			admin := h.admin(globex)
			a := h.approval(globex, "b")
			step := func(ctx context.Context, inst domain.Installation) error {
				switch change {
				case "delivery":
					m := solution("b", false)
					m.Generation++
					_, err := h.svc.ApplyModule(ctx, m)
					return err
				case "revocation":
					return h.svc.Uninstall(ctx, admin, globex, inst.ID)
				default:
					h.store.PutPerson(domain.Person{ID: admin.ID, Organization: globex})
					return nil
				}
			}
			_, err := h.svc.Install(h.ctx, admin, globex, "b", "author", admin.ID, a, step)
			if err == nil {
				t.Fatal("changed approval activated at acknowledgement")
			}
			if err := h.store.Read(h.ctx, func(tx authority.Tx) error {
				inst, err := tx.Installation(authority.StableInstallationID(globex, "b"))
				if err == nil && inst.Status == domain.Active {
					t.Fatal("refused acknowledgement left active authority")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
