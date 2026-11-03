package hopconformance

import (
	"context"
	"sync"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	core "github.com/codefly-dev/core/workcontext"
)

// reservations is the suite's replay store: the reservation contract the hop
// library states (hop.ReservationStore) in memory, shared by every verifier of
// one case and read by the case. It declares itself shared because it is the
// one store those verifiers share, which is what the declaration states. A
// deployment's store is replaypg, whose atomicity and durability over Postgres
// are proven by its own tests; this store proves what the verifier does with
// one.
type reservations struct {
	mu sync.Mutex
	// now is the store's own clock, which a case may set apart from the
	// verifier's.
	now    func() time.Time
	held   map[string]time.Time // nonce to its retention
	active map[string]bool      // nonces whose call still runs
	fail   error                // when set, the store is unavailable
}

func newReservations() *reservations {
	return &reservations{now: time.Now, held: map[string]time.Time{}, active: map[string]bool{}}
}

// Shared marks the store as the one every verifier of a case shares.
func (s *reservations) Shared() bool { return true }

// Consume reserves nonce until retainUntil with no in-flight hold.
func (s *reservations) Consume(_ context.Context, nonce string, retainUntil time.Time) error {
	return s.reserve(nonce, retainUntil, false)
}

// Reserve reserves nonce until retainUntil and holds it until Finish.
func (s *reservations) Reserve(_ context.Context, nonce string, retainUntil time.Time) error {
	return s.reserve(nonce, retainUntil, true)
}

func (s *reservations) reserve(nonce string, retainUntil time.Time, hold bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	// A reservation past its own retention by the store's clock never
	// revives a nonce collection may have removed.
	if !retainUntil.After(s.now()) {
		return refusal.StampWindow
	}
	if _, held := s.held[nonce]; held {
		return core.ErrReplayed
	}
	s.held[nonce] = retainUntil
	if hold {
		s.active[nonce] = true
	}
	return nil
}

// Finish ends the in-flight hold; the reservation stays to its retention.
func (s *reservations) Finish(_ context.Context, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	delete(s.active, nonce)
	return nil
}

// retention is the reservation nonce holds, if any.
func (s *reservations) retention(nonce string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, held := s.held[nonce]
	return until, held
}

// running reports whether a call holding nonce still runs.
func (s *reservations) running(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[nonce]
}

// count is how many nonces the store holds.
func (s *reservations) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.held)
}

// unavailable makes every operation fail with err, as a store that cannot
// answer does; the error names what a caller must never see.
func (s *reservations) unavailable(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}
