package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// A member reads what the solution they use grants: its roles, ceiling and
// installation, read-only. The consent tuple stays an administrator's, and
// a member holding nothing there, or naming a target their organization has
// not installed, is refused by one reason that discloses neither.
func TestAMemberHoldingARoleReviewsTheOfferWithoutItsConsent(t *testing.T) {
	h := newHarness(t)
	maya, tam := h.person("maya"), h.person("tam")

	admin, err := h.svc.ReviewOffer(h.ctx, h.admin(acme), acme, "a")
	if err != nil || admin.Approval.Digest == "" || admin.Installation.ID != h.inst(acme, "a").ID {
		t.Fatalf("the administrator's review: %+v %v", admin.Approval, err)
	}
	for _, target := range []string{"a", "no-such-solution", "store"} {
		_, err := h.svc.ReviewOffer(h.ctx, maya, acme, target)
		code(t, err, domain.Denied)
		if want := `reviewing "` + target + `" requires an administrator or owner of organization "acme", or a role on its installation there`; err.Error() != want {
			t.Fatalf("maya, holding nothing, reviewing %s: %v", target, err)
		}
	}

	h.grant("a", "viewer", "maya")
	h.grantTeam("a", "editor", "team")
	for _, member := range []string{"maya", "tam"} {
		got, err := h.svc.ReviewOffer(h.ctx, h.person(member), acme, "a")
		if err != nil {
			t.Fatalf("%s holds a role on a: %v", member, err)
		}
		if got.Approval != (domain.ConsentApproval{}) {
			t.Fatalf("%s read the consent tuple: %+v", member, got.Approval)
		}
		if got.Installation.ID != admin.Installation.ID || len(got.Module.Roles) != len(admin.Module.Roles) || len(got.Module.Bindings) != len(admin.Module.Bindings) {
			t.Fatalf("%s read another declaration than the administrator: %+v", member, got)
		}
	}
	_, err = h.svc.ReviewOffer(h.ctx, maya, acme, "b")
	refused(t, err, `reviewing "b" requires`)
	_, err = h.svc.Review(h.ctx, maya, acme, "a")
	refused(t, err, "installation administration requires an administrator or owner")
	_, err = h.svc.ReviewOffer(h.ctx, tam, globex, "a")
	refused(t, err, `organization "globex"`)
	_, err = h.svc.ReviewOffer(h.ctx, h.admin(globex), acme, "a")
	refused(t, err, `reviewing "a" requires an administrator or owner of organization "acme"`)

	h.revoke("a", "viewer", "maya", "")
	_, err = h.svc.ReviewOffer(h.ctx, maya, acme, "a")
	refused(t, err, `reviewing "a" requires`)
	if _, err := h.svc.ReviewOffer(h.ctx, tam, acme, "a"); err != nil {
		t.Fatalf("tam's team still holds editor: %v", err)
	}
	if err := h.svc.Uninstall(h.ctx, h.admin(acme), acme, admin.Installation.ID); err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.ReviewOffer(h.ctx, tam, acme, "a")
	refused(t, err, `reviewing "a" requires`)
}
