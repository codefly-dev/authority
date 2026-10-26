package state

import (
	"fmt"
	"slices"
	"sort"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	resources "github.com/codefly-dev/authority/libraries/resources/go"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// refreshRolesLocked recomputes the generated developer role from the
// current delivered catalog (replaced, never accumulated) and writes every
// organisation role to the core's store as authored. Caller holds mu.
func (s *State) refreshRolesLocked() {
	union := s.permissionCatalog()
	for key, role := range s.roles {
		if role.Generated {
			role.Scopes = nil
			for _, sc := range union {
				role.Scopes = append(role.Scopes, Scope{Kind: sc.GetResourceKind(), Actions: slices.Clone(sc.GetActions())})
			}
			s.roles[key] = role
		}
		stored := domain.OrgRole{Organization: role.Organization, Name: role.Name}
		for _, sc := range role.Scopes {
			grants := make([]resources.Grant, 0, len(sc.Resources))
			for _, m := range sc.Resources {
				grants = append(grants, m.Grant())
			}
			stored.Scopes = append(stored.Scopes, domain.RoleScope{Kind: sc.Kind, Actions: slices.Clone(sc.Actions), Resources: grants})
		}
		s.store.PutOrgRole(stored)
	}
}

// RoleScopes is what an organisation role grants as authored, as scopes.
func (s *State) RoleScopes(org, role string) []*basev0.WorkScopeV1 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*basev0.WorkScopeV1
	for _, sc := range s.roles[org+"/"+role].Scopes {
		out = append(out, &basev0.WorkScopeV1{ResourceKind: sc.Kind, Actions: slices.Clone(sc.Actions)})
	}
	return Normalize(out)
}

func (s *State) modules() []Manifest {
	var out []Manifest
	_ = s.read(func(tx authority.Tx) error {
		var err error
		out, err = tx.Modules()
		return err
	})
	return out
}

// permissionCatalog is every concrete (kind, action) a delivered module serves.
func (s *State) permissionCatalog() []*basev0.WorkScopeV1 {
	var union []*basev0.WorkScopeV1
	for _, m := range s.modules() {
		if m.Kind == domain.KindSolution {
			continue
		}
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
	return Normalize(union)
}

// PermissionReport describes a snapshot of delivered generations. Coverage
// means static eligibility only: identity, installations, consent and resource
// visibility are still evaluated at use time. Undelivered kinds are unresolved.
func (s *State) PermissionReport() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lines []string
	modules := s.modules()
	catalog := s.permissionCatalog()
	kinds := map[string]bool{}
	for _, m := range modules {
		if m.Kind == domain.KindSolution {
			continue
		}
		for _, sc := range m.ResourceKinds {
			kinds[sc.GetResourceKind()] = true
		}
	}
	var orgRoles []domain.OrgRole
	for key, role := range s.roles {
		stored := domain.OrgRole{Organization: role.Organization, Name: key}
		for _, sc := range role.Scopes {
			stored.Scopes = append(stored.Scopes, domain.RoleScope{Kind: sc.Kind, Actions: sc.Actions})
			if sc.Kind == AnyKind {
				continue
			}
			for _, action := range sc.Actions {
				if action == AnyAction {
					continue
				}
				if !kinds[sc.Kind] {
					lines = append(lines, fmt.Sprintf("WARN role %s: %s:%s unresolved in current delivery", key, sc.Kind, action))
				} else if !HoldsAction(catalog, sc.Kind, action) {
					lines = append(lines, fmt.Sprintf("WARN role %s: %s:%s is not declared by current delivery", key, sc.Kind, action))
				}
			}
		}
		orgRoles = append(orgRoles, stored)
	}
	for _, m := range modules {
		if len(m.Methods) == 0 {
			lines = append(lines, fmt.Sprintf("WARN %s@%d: no delivered method policies; declared ceilings alone do not admit a call", m.Name, m.Generation))
		}
		for _, sc := range m.ResourceKinds {
			if sc.GetResourceKind() == AnyKind || slices.Contains(sc.GetActions(), AnyAction) {
				lines = append(lines, fmt.Sprintf("WARN %s@%d %s: wildcard ceiling is unresolved; generated developer uses explicit actions only", m.Name, m.Generation, sc.GetResourceKind()))
			}
		}
		roles := map[string][]*basev0.WorkScopeV1{}
		if m.Kind == domain.KindSolution {
			for name, scopes := range m.Roles {
				// Statically an installation-owned scope covers its kind; which
				// ids is each installation's, decided at issue.
				roles["installation/"+name] = Normalize(append(slices.Clone(scopes), m.OwnedRoles[name]...))
			}
		} else {
			for _, role := range orgRoles {
				roles[role.Name] = decide.OrgScopes([]domain.OrgRole{role}, m)
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
				lines = append(lines, fmt.Sprintf("role %s × %s@%d × %s: %s", role, m.Name, m.Generation, method, result))
			}
			if !covered {
				lines = append(lines, fmt.Sprintf("WARN %s@%d %s: no single declared role covers this method", m.Name, m.Generation, method))
			}
		}
	}
	sort.Strings(lines)
	return slices.Compact(lines)
}
