package decide

import (
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// sourceGovernance holds what m declares governs its sources to its roles:
// each scope a whole action on one of the kinds m's manifest declares (never
// a wildcard, an id or an owner), not one it declares shared (no installation
// owns it, so it would govern every installation's sources), and granted by
// one of its roles, so whoever governs holds it on the installation through
// that role. Core's contract reader refuses the same; a host holds the
// delivered declaration to it anyway, because the manifest is what it
// verified.
func sourceGovernance(m domain.Module) error {
	for _, governing := range m.SourceGovernance {
		kind := governing.GetResourceKind()
		if len(governing.GetResourceIds()) > 0 || governing.GetResourceOwnerId() != "" {
			return domain.Refuse("%s governs its sources by %s with resource ids or an owner; a governing scope names a whole kind", m.Name, kind)
		}
		if !slices.ContainsFunc(m.ResourceKinds, func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceKind() == kind }) {
			return domain.Refuse("%s governs its sources by %s, which is not a kind it declares", m.Name, kind)
		}
		if slices.Contains(m.SharedKinds, kind) {
			return domain.Refuse("%s governs its sources by %s, which it declares shared: no installation owns it", m.Name, kind)
		}
		if len(governing.GetActions()) == 0 {
			return domain.Refuse("%s governs its sources by %s with no action", m.Name, kind)
		}
		for _, action := range governing.GetActions() {
			if action == "" || action == scope.AnyAction {
				return domain.Refuse("%s governs its sources by %s:%q; a governing scope names one action, never every one", m.Name, kind, action)
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
