package decide

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	"github.com/codefly-dev/authority/libraries/authority-core/go/scope"
	delivery "github.com/codefly-dev/authority/libraries/delivery/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// ValidateModule holds a delivered module to its contract: a principal, a
// generation, bindings whose lookup and headless scopes stay within invoke;
// a module without a page declares no roles; a solution, or a module page
// that declares roles, declares installer, and every role stays within what
// it serves or consumes through invoke/lookup bindings.
func ValidateModule(m domain.Module) error {
	if err := validateModule(m); err != nil {
		return err
	}
	return noOwners(m)
}

func validateModule(m domain.Module) error {
	if m.Name == "" || m.Principal == "" || m.Generation == 0 {
		return domain.Refuse("a manifest names its module, its principal and a generation")
	}
	seenKinds := map[string]bool{}
	for _, kind := range m.OwnerAwareResourceKinds {
		if m.OwnerAware || seenKinds[kind] || !slices.ContainsFunc(m.ResourceKinds, func(sc *basev0.WorkScopeV1) bool { return sc.GetResourceKind() == kind }) {
			return domain.Refuse("owner-aware resource kinds must be unique served kinds without global owner-awareness")
		}
		seenKinds[kind] = true
	}
	seenSetup := map[string]bool{}
	for _, setup := range m.Setup {
		b, ok := m.Bindings[setup.Binding]
		if m.Kind != domain.KindSolution || !ok || seenSetup[setup.Binding] || b.Audience == m.Principal || len(setup.Methods) == 0 || len(setup.Scopes) == 0 {
			return domain.Refuse("setup requires a solution's unique foreign binding, exact methods and resolved scopes")
		}
		seenSetup[setup.Binding] = true
		seenMethods := map[string]bool{}
		for _, method := range setup.Methods {
			if seenMethods[method] || strings.ContainsAny(method, "*{}") || delivery.ValidateMethodPolicy(method, false, map[string][]string{"setup": {"invoke"}}, false) != nil {
				return domain.Refuse("setup requires unique exact methods")
			}
			seenMethods[method] = true
		}
		for _, text := range setup.Scopes {
			kind, action, ok := strings.Cut(text, ":")
			if !ok || kind == "" || action == "" || !scope.Attenuates(Scopes{{ResourceKind: kind, Actions: []string{action}}}, b.InvokeScopes) {
				return domain.Refuse("setup scopes exceed the binding invoke ceiling")
			}
		}
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
		if len(m.OwnedRoles) > 0 {
			return domain.Refuse("module %q declares installation-owned roles; only a solution declares them", m.Name)
		}
		if len(m.Roles) == 0 {
			return nil
		}
		if !m.Page {
			return domain.Refuse("module %q declares roles and no page; a module's access is the organization's roles unless it declares a page", m.Name)
		}
	}
	if _, ok := m.Roles[domain.InstallerRole]; !ok {
		return &domain.Refusal{Code: domain.Denied, Cause: domain.ErrNoInstallerRole,
			Reason: fmt.Sprintf("%s declares %d role(s) and none is %q: a solution, or a module page declaring roles, declares an installer role", m.Name, len(m.Roles), domain.InstallerRole)}
	}
	grantable := slices.Clone(m.ResourceKinds)
	for _, b := range m.Bindings {
		grantable = append(grantable, b.InvokeScopes...)
		grantable = append(grantable, b.LookupScopes...)
	}
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		scopes := m.Roles[name]
		if len(scopes) == 0 && len(m.OwnedRoles[name]) == 0 {
			return domain.Refuse("role %q of %s grants nothing", name, m.Name)
		}
		if scope.HasOwner(scopes) {
			return domain.Refuse("role %q of %s selects an owner; a role's owner is its installation's principal", name, m.Name)
		}
		if !scope.Attenuates(scopes, grantable) {
			return domain.Refuse("role %q of %s grants beyond what %s serves or explicitly consumes through invoke/lookup bindings", name, m.Name, m.Name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.OwnedRoles)) {
		if _, ok := m.Roles[name]; !ok {
			return domain.Refuse("installation-owned role %q of %s is not declared", name, m.Name)
		}
		for _, sc := range m.OwnedRoles[name] {
			if len(sc.GetResourceIds()) > 0 || sc.GetResourceOwnerId() != "" {
				return domain.Refuse("installation-owned role %q names resource ids or an owner; its installation supplies the ids", name)
			}
		}
		if !scope.Attenuates(m.OwnedRoles[name], grantable) {
			return domain.Refuse("installation-owned role %q grants beyond what %s serves or explicitly consumes", name, m.Name)
		}
	}
	return nil
}

// RoleGated reports whether what a person holds at m is the roles granted on
// its installation: a solution's, or a module page's that declares roles.
// Otherwise it is their organization roles within what m serves.
func RoleGated(m domain.Module) bool {
	return m.Kind == domain.KindSolution || len(m.Roles) > 0
}

// Narrowed reports whether next narrows what previous granted: a binding
// removed, readdressed or cut, owner-aware checking withdrawn, any of its
// roles cut, or a module moved between organization roles and its own. A
// narrowing invalidates capabilities already issued.
func Narrowed(previous, next domain.Module) bool {
	if OwnerAwareNarrowed(previous, next) {
		return true
	}
	for id, old := range previous.Bindings {
		b, ok := next.Bindings[id]
		if !ok || old.Audience != b.Audience || !scope.Attenuates(old.InvokeScopes, b.InvokeScopes) ||
			!scope.Attenuates(old.HeadlessScopes, b.HeadlessScopes) || !scope.Attenuates(old.LookupScopes, b.LookupScopes) {
			return true
		}
	}
	if RoleGated(previous) != RoleGated(next) {
		return true
	}
	for name, scopes := range previous.OwnedRoles {
		if !scope.Attenuates(scopes, next.OwnedRoles[name]) {
			return true
		}
	}
	for name, scopes := range previous.Roles {
		if !scope.Attenuates(scopes, next.Roles[name]) {
			return true
		}
	}
	return false
}

// noOwners refuses a delivery naming a resource owner where none belongs: in
// what a module serves, in a binding's scopes, in a role or in a method's
// requirement. An owner is the authority's to select per installation; read
// owner-blind, it would widen to the whole kind, so it is refused by name.
func noOwners(m domain.Module) error {
	check := func(where string, scopes Scopes) error {
		for _, sc := range scopes {
			if sc.GetResourceOwnerId() != "" {
				return domain.Refuse("%s: %s names resource owner %q; a delivery never selects an owner", where, sc.GetResourceKind(), sc.GetResourceOwnerId())
			}
		}
		return nil
	}
	if err := check(m.Name+" serves", m.ResourceKinds); err != nil {
		return err
	}
	for _, id := range slices.Sorted(maps.Keys(m.Bindings)) {
		b := m.Bindings[id]
		for _, scopes := range []Scopes{b.InvokeScopes, b.HeadlessScopes, b.LookupScopes} {
			if err := check(m.Name+" binding "+id, scopes); err != nil {
				return err
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.Roles)) {
		if err := check(m.Name+" role "+name, m.Roles[name]); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(m.OwnedRoles)) {
		if err := check(m.Name+" installation-owned role "+name, m.OwnedRoles[name]); err != nil {
			return err
		}
	}
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		if err := check(m.Name+" method "+method, m.Methods[method].Requires); err != nil {
			return err
		}
	}
	return nil
}

// Served is what a module serves: the kinds it declares, joined to every
// (kind, action) its methods require of a call, read from its own method
// declarations.
func Served(m domain.Module) Scopes {
	served := slices.Clone(m.ResourceKinds)
	for _, method := range slices.Sorted(maps.Keys(m.Methods)) {
		for _, required := range m.Methods[method].Requires {
			served = append(served, &basev0.WorkScopeV1{ResourceKind: required.GetResourceKind(), Actions: slices.Clone(required.GetActions())})
		}
	}
	return scope.Normalize(served)
}

// OwnerAwareNarrowed uses the existing audience epoch for withdrawal of any kind.
func OwnerAwareNarrowed(previous, next domain.Module) bool {
	if next.OwnerAware {
		return false
	}
	if previous.OwnerAware {
		return true
	}
	return slices.ContainsFunc(previous.OwnerAwareResourceKinds, func(kind string) bool { return !slices.Contains(next.OwnerAwareResourceKinds, kind) })
}
