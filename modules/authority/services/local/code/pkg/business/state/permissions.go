package state

import (
	"fmt"
	"slices"
	"sort"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// refreshDeveloperRoles replaces, never accumulates, the local fixture's
// generated union. It does not assign roles to people or change business roles.
// Caller holds mu. Explicit non-method ceilings remain supported.
func (s *State) refreshDeveloperRoles() {
	union := s.permissionCatalog()
	for key, role := range s.roles {
		if !role.Generated {
			continue
		}
		role.Scopes = nil
		for _, sc := range union {
			role.Scopes = append(role.Scopes, Scope{Kind: sc.GetResourceKind(), Actions: append([]string(nil), sc.GetActions()...)})
		}
		s.roles[key] = role
	}
}

// permissionCatalog contains concrete declarations only. Caller holds mu.
func (s *State) permissionCatalog() []*basev0.WorkScopeV1 {
	var union []*basev0.WorkScopeV1
	for _, m := range s.modules {
		if m.Kind != "solution" {
			for _, sc := range m.ResourceKinds {
				if sc.GetResourceKind() == AnyKind {
					continue
				}
				var actions []string
				for _, action := range sc.GetActions() {
					if action != AnyAction {
						actions = append(actions, action)
					}
				}
				if len(actions) > 0 {
					union = append(union, &basev0.WorkScopeV1{ResourceKind: sc.GetResourceKind(), Actions: actions})
				}
			}
		}
	}
	union = Normalize(union)
	return union
}

// PermissionReport describes a snapshot of delivered generations. Coverage
// means static eligibility only: identity, installations, consent and resource
// visibility are still evaluated at use time. Undelivered kinds are unresolved.
func (s *State) PermissionReport() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lines []string
	catalog := s.permissionCatalog()
	kinds := map[string]bool{}
	for _, m := range s.modules {
		if m.Kind == "solution" {
			continue
		}
		for _, sc := range m.ResourceKinds {
			kinds[sc.GetResourceKind()] = true
		}
	}
	for key, role := range s.roles {
		for _, sc := range role.Scopes {
			if sc.Kind == AnyKind {
				continue
			}
			for _, action := range sc.Actions {
				if action == AnyAction {
					continue
				}
				if !kinds[sc.Kind] {
					lines = append(lines, fmt.Sprintf("WARN role %s: %s:%s unresolved in current delivery", key, sc.Kind, action))
				} else if !holdsAction(catalog, sc.Kind, action) {
					lines = append(lines, fmt.Sprintf("WARN role %s: %s:%s is not declared by current delivery", key, sc.Kind, action))
				}
			}
		}
	}
	for _, m := range s.modules {
		if len(m.Methods) == 0 {
			lines = append(lines, fmt.Sprintf("WARN %s@%d: no delivered method policies; declared ceilings alone do not admit a call", m.Module, m.Generation))
		}
		for _, sc := range m.ResourceKinds {
			if sc.GetResourceKind() == AnyKind || slices.Contains(sc.GetActions(), AnyAction) {
				lines = append(lines, fmt.Sprintf("WARN %s@%d %s: wildcard ceiling is unresolved; generated developer uses explicit actions only", m.Module, m.Generation, sc.GetResourceKind()))
			}
		}
		roles := map[string][]*basev0.WorkScopeV1{}
		if m.Kind == "solution" {
			for name, scopes := range m.Roles {
				// Statically an installation-owned scope covers its kind; which
				// ids is each installation's, decided at issue.
				roles["installation/"+name] = Normalize(append(slices.Clone(scopes), m.OwnedRoles[name]...))
			}
		} else {
			for key, role := range s.roles {
				var scopes []*basev0.WorkScopeV1
				for _, sc := range role.Scopes {
					if sc.Kind == AnyKind {
						for _, kind := range m.ResourceKinds {
							scopes = append(scopes, &basev0.WorkScopeV1{ResourceKind: kind.GetResourceKind(), Actions: sc.Actions})
						}
					} else {
						scopes = append(scopes, &basev0.WorkScopeV1{ResourceKind: sc.Kind, Actions: sc.Actions})
					}
				}
				roles[key] = Intersect(Normalize(scopes), m.ResourceKinds)
			}
		}
		for method := range m.Methods {
			covered := false
			for role, scopes := range roles {
				result := "covered statically; identity, installation and resource checks still apply"
				if err := admitMethod(m, m.Principal, method, scopes); err != nil {
					result = err.Error()
				} else {
					covered = true
				}
				lines = append(lines, fmt.Sprintf("role %s × %s@%d × %s: %s", role, m.Module, m.Generation, method, result))
			}
			if !covered {
				lines = append(lines, fmt.Sprintf("WARN %s@%d %s: no single declared role covers this method", m.Module, m.Generation, method))
			}
		}
	}
	sort.Strings(lines)
	return slices.Compact(lines)
}
