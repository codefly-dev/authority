package decide_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// The installation_role rules core's contract schema used to carry: the
// authority decides role rules, so a manifest declaring an installation role it
// does not have, spelled loosely, or a role named like the "none" marker is
// refused at admission rather than at the first install.
func TestTheInstallationRoleNamesADeclaredRole(t *testing.T) {
	for _, role := range []string{"", domain.NoInstallationRole, domain.AdminRole} {
		m := solution
		m.InstallationRole = role
		if err := decide.ValidateModule(m); err != nil {
			t.Fatalf("installation_role %q: %v", role, err)
		}
	}
	ghost := solution
	ghost.InstallationRole = "ghost"
	refused(t, decide.ValidateModule(ghost), domain.Denied, "not one of its roles")
	spaced := solution
	spaced.InstallationRole = " none "
	refused(t, decide.ValidateModule(spaced), domain.Denied, "surrounding whitespace")
	reserved := solution
	reserved.Roles = map[string][]*basev0.WorkScopeV1{}
	for name, scopes := range solution.Roles {
		reserved.Roles[name] = scopes
	}
	reserved.Roles[domain.NoInstallationRole] = solution.Roles[domain.AdminRole]
	refused(t, decide.ValidateModule(reserved), domain.Denied, "reserved")
}
