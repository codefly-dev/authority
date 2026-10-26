package decide

import (
	"fmt"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
)

// ValidateModule holds a delivered module to its contract: a principal, a
// generation, bindings whose lookup and headless scopes stay within invoke;
// a module declares no roles; a solution declares installer, and every role
// stays within what it serves or consumes through invoke/lookup bindings.
func ValidateModule(m domain.Module) error {
	if m.Name == "" || m.Principal == "" || m.Generation == 0 {
		return domain.Refuse("a manifest names its module, its principal and a generation")
	}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		policy := m.Methods[method]
		requires := map[string][]string{}
		for _, sc := range policy.Requires {
			if len(sc.GetResourceIds()) > 0 || sc.GetResourceOwnerId() != "" {
				return domain.Refuse("%s: %s: method requirements name whole resource kinds; resource ids and owners are not supported", m.Name, method)
			}
			requires[sc.GetResourceKind()] = append(requires[sc.GetResourceKind()], sc.GetActions()...)
		}
		if err := delivery.ValidateMethodPolicy(method, policy.AnyCheckedCaller, requires, false); err != nil {
			return domain.Refuse("%s: %v", m.Name, err)
		}
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		lookupCeiling := b.InvokeScopes
		if len(lookupCeiling) == 0 {
			lookupCeiling = b.HeadlessScopes
		}
		if len(b.LookupScopes) > 0 && !scope.Attenuates(b.LookupScopes, lookupCeiling) {
			return domain.Refuse("binding %s: lookup scopes exceed what the binding may do", id)
		}
		if len(b.InvokeScopes) > 0 && !scope.Attenuates(b.HeadlessScopes, b.InvokeScopes) {
			return domain.Refuse("binding %s: headless scopes exceed invoke scopes", id)
		}
	}
	if m.Kind != domain.KindSolution {
		if len(m.Roles) > 0 {
			return domain.Refuse("module %q declares roles; a module's access is the organization's roles", m.Name)
		}
		return nil
	}
	if _, ok := m.Roles[domain.InstallerRole]; !ok {
		return &domain.Refusal{Code: domain.Denied, Cause: domain.ErrNoInstallerRole,
			Reason: fmt.Sprintf("%s declares %d role(s) and none is %q: a solution declares an installer role", m.Name, len(m.Roles), domain.InstallerRole)}
	}
	grantable := slices.Clone(m.ResourceKinds)
	for _, b := range m.Bindings {
		grantable = append(grantable, b.InvokeScopes...)
		grantable = append(grantable, b.LookupScopes...)
	}
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		scopes := m.Roles[name]
		if len(scopes) == 0 {
			return domain.Refuse("role %q of %s grants nothing", name, m.Name)
		}
		if scope.HasOwner(scopes) {
			return domain.Refuse("role %q of %s selects an owner; a role's owner is its installation's principal", name, m.Name)
		}
		if !scope.Attenuates(scopes, grantable) {
			return domain.Refuse("role %q of %s grants beyond what %s serves or explicitly consumes through invoke/lookup bindings", name, m.Name, m.Name)
		}
	}
	return nil
}

// Narrowed reports whether next narrows what previous granted: a binding
// removed, readdressed or cut, owner-aware checking withdrawn, or any of a
// solution's roles cut. A narrowing invalidates capabilities already issued.
func Narrowed(previous, next domain.Module) bool {
	if previous.OwnerAware && !next.OwnerAware {
		return true
	}
	for id, old := range previous.Bindings {
		b, ok := next.Bindings[id]
		if !ok || old.Audience != b.Audience || !scope.Attenuates(old.InvokeScopes, b.InvokeScopes) ||
			!scope.Attenuates(old.HeadlessScopes, b.HeadlessScopes) || !scope.Attenuates(old.LookupScopes, b.LookupScopes) {
			return true
		}
	}
	if previous.Kind != domain.KindSolution {
		return false
	}
	for name, scopes := range previous.Roles {
		if !scope.Attenuates(scopes, next.Roles[name]) {
			return true
		}
	}
	return false
}
