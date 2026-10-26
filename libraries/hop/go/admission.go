package hop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-client/go/workcontext"
	core "github.com/codefly-dev/core/workcontext"
	"google.golang.org/grpc/metadata"
)

// ReservationStore is a replay store that can hold a single-use admission for
// as long as a call carrying it runs, not only until a fixed instant. The
// verifier reserves at the call's arrival and finishes when its handler
// returns; the store keeps the reservation until Finish AND retainUntil have
// both passed. A store without these operations keeps a nonce to retainUntil,
// and the verifier refuses any consumption that completes past it.
//
// Reserve must refuse atomically, across every replica, a nonce that is already
// held (core.ErrReplayed), including one held by a call still running past
// retainUntil. It must also refuse, at the point the store decides, a
// reservation whose retainUntil has already passed (refusal.StampWindow): a
// reservation delayed past its own horizon must never revive a nonce that
// collection removed. A Finish that fails leaves the reservation held, so a
// failure never reopens admission. Because Reserve refuses on the store's own
// clock any reservation past retainUntil, a store may collect a reservation
// once retainUntil has passed by that clock whether or not its call has
// finished: nothing can reserve that nonce again. replaypg.Store implements
// it, and collects so, so a holder that stops before Finish leaves no
// permanent row.
type ReservationStore interface {
	core.ReplayStore
	Reserve(ctx context.Context, nonce string, retainUntil time.Time) error
	Finish(ctx context.Context, nonce string) error
}

// instant is when a call arrived: on the verifier's clock, and as a monotonic
// mark from which the time since then is measured.
type instant struct{ at, mark time.Time }

func (v *Verifier) instant() instant { return instant{at: v.now(), mark: time.Now()} }

// since is the verifier's clock now, measured from the arrival.
func (i instant) since() time.Time { return i.at.Add(time.Since(i.mark)) }

// storeTimeout bounds one reservation or release, which run detached from the
// call so that their outcome is always known, even for a call that ends.
const storeTimeout = 5 * time.Second

// reserve checks the admission md carries against the instant the call arrived
// and consumes its single-use nonce. It returns the release that ends the
// reservation's in-flight hold, safe to call more than once.
func (v *Verifier) reserve(ctx context.Context, md metadata.MD, method string, arrival instant) (func(), error) {
	if v.replay == nil {
		// A token-only verifier (NewTokenVerifier) holds no replay store, so
		// it can establish no admission.
		return nil, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, refusal.Configuration)
	}
	// The admission is judged at the instant the call arrived, whenever the
	// published key it is signed by is read.
	key, err := v.admissionKey(ctx, md)
	if err != nil {
		return nil, err
	}
	call, err := stamp.Check(md, key, method, v.audience, arrival.at)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, err)
	}
	nonce := call.ReplayKey(key)
	// Retained to expiry plus the clock allowance at least, so a lagging
	// verifier never admits a second delivery of a nonce another released.
	until := time.Unix(call.Expires+int64(stamp.Skew/time.Second), 0)
	release := func() {}
	reserving, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if managed, ok := v.replay.(ReservationStore); ok {
		err = managed.Reserve(reserving, nonce, until)
		var once sync.Once
		release = func() {
			once.Do(func() {
				finishing, cancel := context.WithTimeout(context.Background(), storeTimeout)
				defer cancel()
				// A failed release leaves the reservation held: never reopen.
				_ = managed.Finish(finishing, nonce)
			})
		}
	} else {
		// A store with no completion operation keeps the nonce to its
		// retention and may then evict it. A consumption that only succeeded
		// because that retention had passed found an evicted nonce, not a new
		// one, and is refused on the window: a second delivery never runs.
		err = v.replay.Consume(reserving, nonce, until)
		if err == nil && !arrival.since().Before(until) {
			err = refusal.StampWindow
		}
	}
	if err != nil {
		reason := refusal.StampStore
		switch {
		case errors.Is(err, core.ErrReplayed):
			reason = refusal.StampReplayed
		case errors.Is(err, refusal.StampWindow):
			reason = refusal.StampWindow
		}
		return nil, fmt.Errorf("%w: %w", workcontext.ErrUnauthenticated, reason)
	}
	return release, nil
}

// establish authenticates the Work Context an admitted call carries. A
// refusal releases the reservation's hold: no handler will run for it.
func (v *Verifier) establish(ctx context.Context, md metadata.MD, release func()) (Identity, error) {
	id, err := v.VerifyToken(ctx, first(md, WorkContextKey))
	if err == nil {
		err = sameAsStamped(md, id)
	}
	if err != nil {
		release()
		return Identity{}, err
	}
	// An admission carrying an advisory refusal is refused by stamp.Check, so
	// an admitted call never has one: diagnostic identity is never authority.
	return id, nil
}

type admissionKey struct{}

// admission is one call's single-use reservation, from the instant the call
// arrived to the instant its handler returned.
type admission struct {
	verifier *Verifier
	method   string
	md       metadata.MD
	reserved chan struct{} // closed once release and err are set
	release  func()
	err      error

	mu             sync.Mutex
	running, ended bool
}

// start claims the admission for the handler, unless the call already ended.
func (a *admission) start() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running || a.ended {
		return false
	}
	a.running = true
	return true
}

// abandon releases the hold of a call that ended before its handler started,
// such as one cancelled while its body was arriving. A call whose handler
// started is released when the handler returns, never by its cancellation.
func (a *admission) abandon() {
	a.mu.Lock()
	if a.running || a.ended {
		a.mu.Unlock()
		return
	}
	a.ended = true
	a.mu.Unlock()
	<-a.reserved
	if a.err == nil {
		a.release()
	}
}

// finish releases the hold once the handler has returned.
func (a *admission) finish() {
	a.mu.Lock()
	a.ended = true
	a.mu.Unlock()
	a.release()
}

func finishAdmission(ctx context.Context) {
	if a, ok := ctx.Value(admissionKey{}).(*admission); ok {
		a.finish()
	}
}
