package decide

import (
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// sourceGovernance holds what m declares governs its sources to its approved
// roles. Only a solution declares it: a solution's installation is approved
// by an administrator, so a delivery that adds or moves a governing scope
// waits for that approval (Widens); a module page's installations are
// composed and never approved, so nothing would. Each scope is a whole action
// (never a wildcard, an id or an owner) on one of m's own kinds, one its own
// ceiling names literally (served here, not underwritten by a binding), not
// one it declares shared (no installation owns it, so it would govern every
// installation's sources), granted directly by one of its roles and reached
// by none through a binding, so whoever governs holds it on the installation
// itself. Core's contract reader refuses the same; a host holds the delivered
// declaration to it anyway, because the manifest is what it verified.
func sourceGovernance(m domain.Module) error {
	if len(m.SourceGovernance) > 0 && m.Kind != domain.KindSolution {
		return domain.Refuse("%s is a %s and declares scopes that govern its sources; only a solution, whose installations an administrator approves, governs sources", m.Name, m.Kind)
	}
	for _, governing := range m.SourceGovernance {
		kind := governing.GetResourceKind()
		if len(governing.GetResourceIds()) > 0 || governing.GetResourceOwnerId() != "" {
			return domain.Refuse("%s governs its sources by %s with resource ids or an owner; a governing scope names a whole kind", m.Name, kind)
		}
		i := slices.IndexFunc(m.ResourceKinds, func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceKind() == kind })
		if i < 0 {
			return domain.Refuse("%s governs its sources by %s, which is not a kind it declares", m.Name, kind)
		}
		if slices.Contains(m.SharedKinds, kind) {
			return domain.Refuse("%s governs its sources by %s, which it declares shared: no installation owns it", m.Name, kind)
		}
		for role, bindings := range m.Through {
			for binding, scopes := range bindings {
				if slices.ContainsFunc(scopes, func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceKind() == kind }) {
					return domain.Refuse("%s governs its sources by %s, which role %s reaches through binding %s: a governing scope is held on the installation itself", m.Name, kind, role, binding)
				}
			}
		}
		if len(governing.GetActions()) == 0 {
			return domain.Refuse("%s governs its sources by %s with no action", m.Name, kind)
		}
		for _, action := range governing.GetActions() {
			if action == "" || action == scope.AnyAction {
				return domain.Refuse("%s governs its sources by %s:%q; a governing scope names one action, never every one", m.Name, kind, action)
			}
			if !slices.Contains(m.ResourceKinds[i].GetActions(), action) {
				return domain.Refuse("%s governs its sources by %s:%s, which its own ceiling does not name", m.Name, kind, action)
			}
			if !GrantedByARole(m, kind, action) {
				return domain.Refuse("%s governs its sources by %s:%s, which none of its roles grants", m.Name, kind, action)
			}
		}
	}
	return nil
}

// GrantedByARole reports whether one of m's roles grants action on the whole
// of kind: what a person holding that role is issued on an installation.
func GrantedByARole(m domain.Module, kind, action string) bool {
	asked := []*basev0.WorkScopeV1{{ResourceKind: kind, Actions: []string{action}}}
	for _, scopes := range m.Roles {
		if scope.Attenuates(asked, scopes) {
			return true
		}
	}
	return false
}

// Governs reports whether m declares kind:action among the scopes that govern
// its sources.
func Governs(m domain.Module, kind, action string) bool {
	return slices.ContainsFunc(m.SourceGovernance, func(sc *basev0.WorkScopeV1) bool {
		return sc.GetResourceKind() == kind && slices.Contains(sc.GetActions(), action)
	})
}
