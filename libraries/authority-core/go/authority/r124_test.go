package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// Another organization's installation and an installation nobody has answer
// a role change with the same words.
func TestAForeignAndAnAbsentInstallationAnswerAlike(t *testing.T) {
	h := newHarness(t)
	foreign := h.inst(globex, "a").ID
	_, errForeign := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: foreign, Role: "viewer", PersonID: "maya"})
	_, errAbsent := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: foreign[:len(foreign)-1] + "0", Role: "viewer", PersonID: "maya"})
	code(t, errForeign, domain.Denied)
	code(t, errAbsent, domain.Denied)
	strip := func(err error, id string) string { return err.Error()[len("installation "+id):] }
	if strip(errForeign, foreign) != strip(errAbsent, foreign[:len(foreign)-1]+"0") {
		t.Fatalf("foreign %q, absent %q", errForeign, errAbsent)
	}
}

