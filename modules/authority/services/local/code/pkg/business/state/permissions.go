package state

import (
	"fmt"
	"slices"
	"sort"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

func (s *State) modules() []Manifest {
	var out []Manifest
	_ = s.read(func(tx authority.Tx) error {
		var err error
		out, err = tx.Modules()
		return err
	})
	return out
}

// PermissionReport describes a snapshot of delivered generations: for each
// method a module declares, which of the module's own roles covers it
// statically. Coverage means static eligibility only: identity, installations,
// consent and resource visibility are still evaluated at use time. A module
// that declares no roles is reached through the roles of the installations
// that bind it and through nothing else, which this report says rather than
// follows; no organisation role covers anything.
func (s *State) PermissionReport() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lines []string
	for _, m := range s.modules() {
		if len(m.Methods) == 0 {
			lines = append(lines, fmt.Sprintf("WARN %s@%d: no delivered method policies; declared ceilings alone do not admit a call", m.Name, m.Generation))
		}
		for _, sc := range m.ResourceKinds {
			if sc.GetResourceKind() == AnyKind || slices.Contains(sc.GetActions(), AnyAction) {
				lines = append(lines, fmt.Sprintf("WARN %s@%d %s: wildcard ceiling is unresolved", m.Name, m.Generation, sc.GetResourceKind()))
			}
		}
		roles := map[string][]*basev0.WorkScopeV1{}
		for name, scopes := range m.Roles {
			// Statically an installation-owned scope covers its kind; which
			// ids is each installation's, decided at issue.
			roles["installation/"+name] = Normalize(slices.Concat(scopes, m.OwnedRoles[name], m.AudienceRoles[name][m.Principal]))
		}
		for method := range m.Methods {
			covered := false
			for role, scopes := range roles {
				result := "covered statically; identity, installation and resource checks still apply"
				if err := classify(decide.AdmitMethod(m, method, scopes)); err != nil {
					result = err.Error()
				} else {
					covered = true
				}
				lines = append(lines, fmt.Sprintf("role %s × %s@%d × %s: %s", role, m.Name, m.Generation, method, result))
			}
			switch {
			case covered:
			case !decide.RoleGated(m):
				lines = append(lines, fmt.Sprintf("%s@%d %s: declares no roles; reached through a role on an installation that binds it, never an organisation role", m.Name, m.Generation, method))
			default:
				lines = append(lines, fmt.Sprintf("WARN %s@%d %s: no single declared role covers this method", m.Name, m.Generation, method))
			}
		}
	}
	sort.Strings(lines)
	return slices.Compact(lines)
}
