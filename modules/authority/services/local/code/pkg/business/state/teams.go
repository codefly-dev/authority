package state

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/decide"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	fixturecomposition "github.com/codefly-dev/authority/libraries/fixture-composition/go"
)

// EveryTarget is the target of a fixture row standing for every role-gated
// target the run composes (fixturecomposition.Installation).
const EveryTarget = fixturecomposition.EveryTarget

// standingKey is an explicit row's (organisation, target).
func standingKey(org, target string) string { return org + "/" + target }

// SeatRoleTeams holds every active role-gated installation to what the
// fixture seats on it: each role its target declares granted to its
// conventional `<target>-<role>` team (the core's GrantRoleTeamsAsHost; the
// team exists in this host's directory first), and the people the fixture
// names for that role seated in that team — the members of a row standing
// for every target at that organisation, and of a row naming the target.
// It installs nothing: a module page is installed by composition, a solution
// by a row naming it (its agent role is a consent) or by an administrator at
// the edge's setup page, and each is seated the moment it is active.
//
// It is idempotent and runs after the fixture loads, after a manifest
// applies, after a fixture installation performs and after a person
// installs: delivery order never decides who holds a team. It answers one
// line per installation seated, for the boot log.
func (s *State) SeatRoleTeams(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	templates := slices.Clone(s.every)
	explicit := maps.Clone(s.members)
	s.mu.RUnlock()
	if len(templates) == 0 && len(explicit) == 0 {
		return nil, nil
	}
	var installs []Installation
	if err := s.read(func(tx authority.Tx) (err error) { installs, err = tx.Installations(""); return err }); err != nil {
		return nil, err
	}
	var lines []string
	for _, inst := range installs {
		m, composed := s.Module(inst.Target)
		if inst.Status != Active || !composed || !decide.RoleGated(m) {
			continue
		}
		seated := map[string][]string{}
		for _, t := range templates {
			if t.Organization == inst.Organization {
				for role, people := range t.Members {
					seated[role] = append(seated[role], people...)
				}
			}
		}
		for role, people := range explicit[standingKey(inst.Organization, inst.Target)] {
			seated[role] = append(seated[role], people...)
		}
		if len(seated) == 0 && !slices.ContainsFunc(templates, func(t FixtureInstallation) bool { return t.Organization == inst.Organization }) {
			continue
		}
		teams, err := s.svc.RoleTeamsOf(ctx, inst.ID)
		if err != nil {
			return nil, fmt.Errorf("fixture: the teams of %s at %s: %w", inst.Target, inst.Organization, classify(err))
		}
		s.mu.Lock()
		for _, team := range teams {
			s.store.PutTeam(inst.Organization, team)
		}
		s.mu.Unlock()
		if _, err := s.svc.GrantRoleTeamsAsHost(ctx, inst.ID); err != nil {
			return nil, fmt.Errorf("fixture: the teams of %s at %s: %w", inst.Target, inst.Organization, classify(err))
		}
		line := fmt.Sprintf("seats %s at %s:", inst.Target, inst.Organization)
		for _, role := range slices.Sorted(maps.Keys(teams)) {
			people := slices.Compact(slices.Sorted(slices.Values(seated[role])))
			for _, id := range people {
				s.seat(id, inst.Organization, teams[role])
			}
			line += fmt.Sprintf(" %s %v", teams[role], people)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// seat puts person in team in this host's directory, if they are a member of
// org and not seated already; the core reads membership at each decision.
func (s *State) seat(person, org, team string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.people[person]
	if !ok || p.Organization != org || slices.Contains(p.Teams, team) {
		return
	}
	p.Teams = append(slices.Clone(p.Teams), team)
	s.people[person] = p
	s.store.PutPerson(domain.Person{ID: p.ID, Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams)})
}

// keepStandingLocked records what a fixture row seats: a row standing for
// every target as a template, a row naming its target by (organisation,
// target), with its members. Each person named is a member of the row's organisation
// in the fixture, or the fixture is refused by name. Caller holds mu.
func (s *State) keepStandingLocked(i FixtureInstallation) error {
	people := []string{i.Owner}
	for _, more := range i.Members {
		people = append(people, more...)
	}
	for _, id := range people {
		if p, ok := s.people[id]; !ok || p.Organization != i.Organization {
			return fmt.Errorf("fixture: the installation of %s at %s names %q, who is not a person of %s", i.Target, i.Organization, id, i.Organization)
		}
	}
	if i.Target == EveryTarget {
		s.every = append(s.every, i)
		return nil
	}
	if s.named == nil {
		s.named, s.members = map[string]bool{}, map[string]map[string][]string{}
	}
	s.named[standingKey(i.Organization, i.Target)] = true
	if len(i.Members) > 0 {
		s.members[standingKey(i.Organization, i.Target)] = i.Members
	}
	return nil
}
