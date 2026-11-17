package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// A grant stays revocable after its person left the organization, and the
// revoke ends their access for good if they return.
func TestAGrantWhosePersonLeftIsStillRevoked(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "user", "maya")
	h.store.DeletePerson("maya")
	h.revoke("a", "user", "maya", "")
	h.store.PutPerson(domain.Person{ID: "maya", Organization: acme})
	_, err := h.root("maya", "a")
	refused(t, err, "holds no role")
}

// Another organization's installation and an installation nobody has answer
// a role change with the same words.
func TestAForeignAndAnAbsentInstallationAnswerAlike(t *testing.T) {
	h := newHarness(t)
	foreign := h.inst(globex, "a").ID
	_, errForeign := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: foreign, Role: "user", PersonID: "maya"})
	_, errAbsent := h.svc.GrantRole(h.ctx, h.person("alex"), authority.RoleRequest{Organization: acme, InstallationID: foreign[:len(foreign)-1] + "0", Role: "user", PersonID: "maya"})
	code(t, errForeign, domain.Denied)
	code(t, errAbsent, domain.Denied)
	strip := func(err error, id string) string { return err.Error()[len("installation "+id):] }
	if strip(errForeign, foreign) != strip(errAbsent, foreign[:len(foreign)-1]+"0") {
		t.Fatalf("foreign %q, absent %q", errForeign, errAbsent)
	}
}

// A grant stays revocable on an uninstalled installation, whose reinstall
// reuses its id, and when its role is no longer declared, which a later
// generation may declare again: neither door revives it. A solution always
// declares its two roles, so the role retired is a module page's, which
// stops declaring roles and declares them again.
func TestARevokeOutlivesUninstallAndARetiredRole(t *testing.T) {
	h := newHarness(t)
	id := h.inst(acme, "a").ID
	h.grant("a", "user", "maya")
	if err := h.svc.UninstallAsHost(h.ctx, acme, id); err != nil {
		t.Fatal(err)
	}
	h.revoke("a", "user", "maya", "")
	if again := h.install(acme, "a"); again.ID != id {
		t.Fatalf("the reinstall is %s, not %s", again.ID, id)
	}
	_, err := h.root("maya", "a")
	refused(t, err, "holds no role")

	if _, err := h.svc.ApplyModule(h.ctx, pageModule(1, true)); err != nil {
		t.Fatal(err)
	}
	h.grant("pages", "user", "maya")
	h.must(h.root("maya", "pages"))
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(2, false)); err != nil {
		t.Fatal(err)
	}
	h.revoke("pages", "user", "maya", "")
	if _, err := h.svc.ApplyModule(h.ctx, pageModule(3, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.approvePage(h.svc, "alex"); err != nil {
		t.Fatal(err)
	}
	_, err = h.root("maya", "pages")
	refused(t, err, "holds no role")
}
