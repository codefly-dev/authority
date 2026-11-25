package state

import (
	"context"
	"fmt"
	"slices"

	"github.com/codefly-dev/authority/libraries/authority-core/go/obintoken"
	"github.com/google/uuid"
)

// OpenAdmitted answers the session a platform token is on this host, opening
// it the first time the token is admitted (obintoken.Adapter.Admit): a role
// view of the person the token names, on the one installation and as the one
// role it names, ending no later than the token does.
//
// The core decides it as it decides any role view, from this host's own
// grants: a person who does not hold the role here is refused, whatever the
// token says, and a role revoked here later ends what the session was issued,
// as it does for a person who signed in. The session behind the view is the
// person's own and is handed to nobody.
//
// A token whose session ended (EndAdmitted, the person's own End, its expiry)
// opens no other: it is refused from then on.
func (s *State) OpenAdmitted(ctx context.Context, adm obintoken.Admission) (Session, error) {
	if adm.TokenID == "" {
		return Session{}, fmt.Errorf("%w: the admission names no token", ErrUnauthenticated)
	}
	s.mu.Lock()
	if id, known := s.admitted[adm.TokenID]; known {
		sess, open := s.openLocked(id)
		s.mu.Unlock()
		if !open {
			return Session{}, fmt.Errorf("%w: the session this token opened has ended", ErrUnauthenticated)
		}
		return sess, nil
	}
	p, known := s.people[adm.Person]
	if !known || p.Organization != adm.Organization {
		s.mu.Unlock()
		return Session{}, fmt.Errorf("%w: the token names no person of %s", ErrUnauthenticated, adm.Organization)
	}
	now := s.svc.Now()
	expires := now.Add(SessionLifetime)
	if adm.ExpiresAt.Before(expires) {
		expires = adm.ExpiresAt
	}
	if !now.Before(expires) {
		s.mu.Unlock()
		return Session{}, fmt.Errorf("%w: the token expired", ErrUnauthenticated)
	}
	name := p.Name
	if name == "" {
		name = p.Email
	}
	own := Session{PersonDisplayName: name, OrganizationDisplayName: s.orgs[p.Organization], ID: uuid.NewString(), Person: p.ID,
		Organization: p.Organization, Roles: slices.Clone(p.Roles), Teams: slices.Clone(p.Teams), ExpiresAt: expires}
	s.sessions[own.ID] = own
	s.mu.Unlock()

	view, err := s.OpenRoleView(ctx, own.ID, adm.Installation, []string{adm.Role})
	if err != nil {
		_ = s.EndSession(own.ID)
		return Session{}, err
	}
	s.mu.Lock()
	if first, raced := s.admitted[adm.TokenID]; raced {
		// The same token admitted twice at once: one session stands.
		sess, open := s.openLocked(first)
		s.mu.Unlock()
		_ = s.EndSession(own.ID)
		if !open {
			return Session{}, fmt.Errorf("%w: the session this token opened has ended", ErrUnauthenticated)
		}
		return sess, nil
	}
	s.admitted[adm.TokenID] = view.ID
	s.mu.Unlock()
	return view, nil
}

// EndAdmitted ends the session the platform token named tokenID opened, and
// with it every capability it was issued; a token that opened none is
// nothing. The token opens no session again.
func (s *State) EndAdmitted(tokenID string) {
	s.mu.RLock()
	view, known := s.admitted[tokenID]
	own := s.sessions[view].Parent
	s.mu.RUnlock()
	if !known {
		return
	}
	// The view's own session ends both; an already ended one is nothing.
	_ = s.EndSession(own)
}
