package state

import (
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// SessionLifetime is how long a sign-in lasts: every session carries the
// moment it ends on its own, this long after it was opened. A role view or a
// cast carries the expiry of the session it was opened from.
const SessionLifetime = 12 * time.Hour

// openLocked is the session id names when it is open: recorded, and not past
// its expiry on the core's clock. It is the one read of a session, so an
// ended or expired bearer is unauthenticated wherever a session is read.
// Caller holds mu.
func (s *State) openLocked(id string) (Session, bool) {
	sess, ok := s.sessions[id]
	if !ok || sess.Ended || !s.svc.Now().Before(sess.ExpiresAt) {
		return Session{}, false
	}
	return sess, true
}

// keepChildLocked records sess as opened from parent, ending no later than it,
// unless parent ended or expired while the core decided. Caller holds mu.
func (s *State) keepChildLocked(parent string, sess Session) (Session, error) {
	from, open := s.openLocked(parent)
	if !open {
		return Session{}, fmt.Errorf("%w: an open session is required", ErrUnauthenticated)
	}
	sess.Parent, sess.ExpiresAt = parent, from.ExpiresAt
	s.sessions[sess.ID] = sess
	return sess, nil
}

// EndSession ends the open session id names and every session opened from it,
// transitively: its role views and casts, and theirs. An ended session remains
// in the ledger so its bearer and issued capabilities stay refused. The session
// it was itself opened from is untouched.
func (s *State) EndSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, open := s.openLocked(id); !open {
		return fmt.Errorf("%w: an open session is required", ErrUnauthenticated)
	}
	ending := []string{id}
	for len(ending) > 0 {
		next := ending[0]
		ending = ending[1:]
		session := s.sessions[next]
		session.Ended = true
		s.sessions[next] = session
		for child, sess := range s.sessions {
			if sess.Parent == next {
				ending = append(ending, child)
			}
		}
	}
	return nil
}

// GrantEpoch is the grant epoch of who the open session id names acts as: a
// digest of what the core answers that session holds now. It covers the
// person as this host's directory reads them (organisation roles and teams),
// each installation the session holds a role on (through its role view or
// cast) with its revision, its target's delivered generation and the roles
// held, and each installation by composition of a module that declares no
// roles. So it differs whenever a role is granted or revoked to the person, a
// team of theirs or the team a cast acts as, when they leave a team, and when
// an installation is made, upgraded or ended; it is the same while none of
// that changed. A session the core refuses to read (a cast that no longer
// holds) holds nothing, and its epoch says so.
func (s *State) GrantEpoch(ctx context.Context, id string) (string, error) {
	caller, err := s.Caller(id)
	if err != nil {
		return "", err
	}
	s.mu.RLock()
	p := s.people[caller.ID]
	s.mu.RUnlock()
	h := sha256.New()
	fmt.Fprintf(h, "person %q at %q roles %q teams %q\n", caller.ID, caller.Organization, slices.Sorted(slices.Values(p.Roles)), slices.Sorted(slices.Values(p.Teams)))
	generation := func(target string) uint64 {
		m, _ := s.Module(target)
		return m.Generation
	}
	held, err := s.svc.HeldInstallations(ctx, caller, caller.Organization)
	if _, refused := domain.CodeOf(err); refused {
		fmt.Fprintf(h, "refused\n")
		return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
	} else if err != nil {
		return "", err
	}
	for _, i := range held {
		fmt.Fprintf(h, "held %q revision %d generation %d roles %q\n", i.Installation.ID, i.Installation.Revision, generation(i.Installation.Target), i.Roles)
	}
	composed, err := s.svc.ComposedInstallations(ctx, caller, caller.Organization)
	if _, refused := domain.CodeOf(err); err != nil && !refused {
		return "", err
	}
	for _, i := range composed {
		fmt.Fprintf(h, "composed %q revision %d generation %d\n", i.ID, i.Revision, generation(i.Target))
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
