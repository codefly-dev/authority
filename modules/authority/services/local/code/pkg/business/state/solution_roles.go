package state

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// PersonSolutionScopes returns the person's full effective installation roles,
// including declared consumed permissions. It never reads organization roles.
// Issuers fence this read with their existing authorization revision checks.
func (s *State) PersonSolutionScopes(person, solution string) ([]*basev0.WorkScopeV1, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.people[person]
	if !ok {
		return nil, fmt.Errorf("%w: person", ErrUnknown)
	}
	m, err := s.moduleByPrincipal(solution)
	if err != nil {
		return nil, err
	}
	if m.Kind != "solution" {
		return nil, fmt.Errorf("%w: %s is not a solution", ErrForbidden, solution)
	}
	return s.personSolutionScopes(p, m), nil
}

// personSolutionScopes uses the caller's state lock. Owners hold installer;
// granted team members hold the selected role; both sources may contribute.
func (s *State) personSolutionScopes(p Person, m Manifest) []*basev0.WorkScopeV1 {
	var held []*basev0.WorkScopeV1
	for _, inst := range s.entitled(p) {
		if inst.Target != m.Module {
			continue
		}
		if inst.Owner == p.ID {
			held = append(held, roleGrants(m, InstallerRole, inst)...)
		}
		for _, team := range inst.Teams {
			if slices.Contains(p.Teams, team) {
				held = append(held, roleGrants(m, inst.Role, inst)...)
				break
			}
		}
	}
	return Normalize(held)
}

// roleGrants is what role grants on one installation of m: its declared
// scopes, and each installation-owned scope limited to the ids inst owns of
// that kind. A kind it owns nothing of grants nothing: an empty id list would
// read as the whole kind, so such a scope is dropped, never emitted.
func roleGrants(m Manifest, role string, inst Installation) []*basev0.WorkScopeV1 {
	out := slices.Clone(m.Roles[role])
	for _, scope := range m.OwnedRoles[role] {
		if ids := inst.Owned[scope.GetResourceKind()]; len(ids) > 0 {
			out = append(out, &basev0.WorkScopeV1{ResourceKind: scope.GetResourceKind(), Actions: slices.Clone(scope.GetActions()), ResourceIds: slices.Clone(ids)})
		}
	}
	return out
}

// AttachResource records that id of kind was created or attached through one
// installation. candidates are the installations the presenting capability's
// verified provenance names; exactly one active installation at tenant must
// remain. Attaching only widens what an installation-owned scope covers, so no
// revision moves: every capability already issued names its own ids.
func (s *State) AttachResource(tenant string, candidates []string, kind, id string) (string, error) {
	candidates = slices.Compact(slices.Sorted(slices.Values(candidates)))
	switch len(candidates) {
	case 0:
		return "", fmt.Errorf("%w: the capability was issued through no installation, so none owns %s %q", ErrForbidden, kind, id)
	case 1:
	default:
		return "", fmt.Errorf("%w: the capability was issued through %d installations (%s); an attachment has exactly one owner", ErrForbidden, len(candidates), strings.Join(candidates, ", "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inst, ok := s.installations[candidates[0]]
	if !ok || inst.Organization != tenant || inst.Status != Active {
		return "", fmt.Errorf("%w: installation %s is not active at %s, so it owns nothing new", ErrForbidden, candidates[0], tenant)
	}
	if slices.Contains(inst.Owned[kind], id) {
		return inst.ID, nil
	}
	owned := maps.Clone(inst.Owned)
	if owned == nil {
		owned = map[string][]string{}
	}
	owned[kind] = slices.Sorted(slices.Values(append(slices.Clone(inst.Owned[kind]), id)))
	inst.Owned = owned
	s.installations[inst.ID] = inst
	return inst.ID, nil
}
