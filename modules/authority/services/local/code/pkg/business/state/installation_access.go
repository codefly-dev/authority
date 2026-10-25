package state

import (
	"fmt"
	"slices"
)

// RequireAdministrator authenticates the session and reads the person's current
// organization roles, rather than trusting the roles captured at sign-in.
func (s *State) RequireAdministrator(session, org string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[session]
	if !ok {
		return fmt.Errorf("%w: an open session is required", ErrUnauthenticated)
	}
	person, ok := s.people[sess.Person]
	if !ok || person.Organization != org || (!slices.Contains(person.Roles, "admin") && !slices.Contains(person.Roles, "owner")) {
		return fmt.Errorf("%w: installation administration requires an administrator or owner of organization %q", ErrForbidden, org)
	}
	return nil
}

// RequireInstallation distinguishes an uninstalled audience from a person who
// holds nothing there. The issuer fences this read with authorization revision.
func (s *State) RequireInstallation(org, module, audience string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inst, ok := s.installations[InstallationID(org, module)]
	if !ok || inst.Status != Active {
		return fmt.Errorf("%w: audience %q is not installed in this organization, so there is no installation to seal the capability to", ErrNotInstalled, audience)
	}
	return nil
}
