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

// Owned ids travel in every capability that holds them, so they are bounded:
// an installation owns at most MaxOwnedPerKind resources of one kind, each id
// at most MaxResourceIDBytes long. Past either, AttachResource refuses by name.
const (
	MaxOwnedPerKind    = 32
	MaxResourceIDBytes = 128
)

// AttachResource records that id of kind now belongs to one installation. candidates are the installations the presenting capability's
// verified provenance names, and revision is the authorization revision it was
// minted at; exactly one active installation at tenant must remain, at the
// tenant's current revision, checked under the write lock so a capability from
// before an uninstall never attaches into the reinstalled installation. A
// resource has one owner in a tenant: an id another installation owns is
// refused until its serving module detaches it. Attaching only widens what an installation-owned scope
// covers, so no revision moves: every capability already issued names its ids.
func (s *State) AttachResource(tenant string, revision uint64, candidates []string, kind, id string) (string, error) {
	if err := validResourceID(id); err != nil {
		return "", err
	}
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
	if current := s.revisions[tenant] + 1; revision != current {
		return "", fmt.Errorf("%w: authorization revision superseded: the capability was minted at revision %d, %s is at %d", ErrForbidden, revision, tenant, current)
	}
	inst, ok := s.installations[candidates[0]]
	if !ok || inst.Organization != tenant || inst.Status != Active {
		return "", fmt.Errorf("%w: installation %s is not active at %s, so it owns nothing new", ErrForbidden, candidates[0], tenant)
	}
	if slices.Contains(inst.Owned[kind], id) {
		return inst.ID, nil
	}
	for _, other := range s.installations {
		if other.ID != inst.ID && other.Organization == tenant && slices.Contains(other.Owned[kind], id) {
			return "", fmt.Errorf("%w: %s %q is owned by installation %s; a resource has one owner in an organisation", ErrForbidden, kind, id, other.ID)
		}
	}
	if len(inst.Owned[kind]) >= MaxOwnedPerKind {
		return "", fmt.Errorf("%w: installation %s already owns %d of %s, the most a capability carries", ErrForbidden, inst.ID, MaxOwnedPerKind, kind)
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

// DetachResource releases id of kind from whichever installation of tenant
// owns it, answering that installation, or nothing when none does. Releasing
// narrows what the owner's roles grant, so its revision and the tenant's move:
// a capability issued before never carries the released id on.
func (s *State) DetachResource(tenant, kind, id string) (string, error) {
	if err := validResourceID(id); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[tenant]; !ok {
		return "", fmt.Errorf("%w: organization %q", ErrUnknown, tenant)
	}
	for _, inst := range s.installations {
		if inst.Organization != tenant || !slices.Contains(inst.Owned[kind], id) {
			continue
		}
		owned := maps.Clone(inst.Owned)
		owned[kind] = slices.DeleteFunc(slices.Clone(owned[kind]), func(held string) bool { return held == id })
		inst.Owned = owned
		inst.Revision++
		s.installations[inst.ID] = inst
		s.revisions[tenant]++
		return inst.ID, nil
	}
	return "", nil
}

// validResourceID holds an owned id to core's scope-value rule (non-empty,
// no surrounding whitespace, no NUL, CR, LF or tab), refuses the wildcard
// character, and bounds its length. Ids are opaque and compared byte for byte.
func validResourceID(id string) error {
	switch {
	case id == "" || strings.TrimSpace(id) != id || strings.ContainsAny(id, "\x00\r\n\t*"):
		return fmt.Errorf("%w: resource id %q is not a usable id (empty, surrounding whitespace, or a NUL, CR, LF, tab or *)", ErrForbidden, id)
	case len(id) > MaxResourceIDBytes:
		return fmt.Errorf("%w: resource id is %d bytes; an installation-owned id is at most %d", ErrForbidden, len(id), MaxResourceIDBytes)
	}
	return nil
}
