package state

import (
	"fmt"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"slices"
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
			held = append(held, m.Roles[InstallerRole]...)
		}
		for _, team := range inst.Teams {
			if slices.Contains(p.Teams, team) {
				held = append(held, m.Roles[inst.Role]...)
				break
			}
		}
	}
	return Normalize(held)
}
