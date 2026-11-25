package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

// RevokeRole is idempotent, so its success is no proof a grant was removed:
// RevokeRoleReporting says whether one was.
func TestRevokingARoleReportsWhetherAGrantWasRemoved(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	r := authority.RoleRequest{Organization: acme, InstallationID: h.inst(acme, "a").ID, Role: "user", PersonID: "maya"}
	revoke := func() bool {
		t.Helper()
		_, removed, err := h.svc.RevokeRoleReporting(h.ctx, h.person("alex"), r)
		if err != nil {
			t.Fatal(err)
		}
		return removed
	}
	if revoke() {
		t.Fatal("revoking a grant nobody holds reported a removal")
	}
	h.grant("a", "user", "maya")
	if !revoke() {
		t.Fatal("revoking a standing grant reported no removal")
	}
	if revoke() {
		t.Fatal("revoking it a second time reported a removal")
	}
	// Another person's grant of the same role is not this one.
	h.grant("a", "user", "remi")
	if revoke() {
		t.Fatal("another person's grant was reported as this one's removal")
	}
	// A refused revoke reports nothing.
	if _, removed, err := h.svc.RevokeRoleReporting(h.ctx, h.person("maya"), authority.RoleRequest{Organization: acme, InstallationID: r.InstallationID, Role: "user", PersonID: "remi"}); err == nil || removed {
		t.Fatalf("a member revoking another's role: removed=%t, %v", removed, err)
	}
}
