package conformance

import (
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// Clock is a case's frozen host clock. Wire Now into the host's existing
// issuance and verification clock seams. It is safe for concurrent RPCs.
// It must never be installed in a process-global clock shared with other cases.
type Clock struct {
	mu  sync.RWMutex
	now time.Time
}

// NewClock starts a controlled clock at now.
func NewClock(now time.Time) *Clock { return &Clock{now: now} }

func (c *Clock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

// Set moves only this case's host clock, including backwards to restore it.
func (c *Clock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// Factory creates a fully isolated host for one scenario, after t.Parallel.
// Use t.Cleanup for its server, connections and store. All mutable state,
// including organizations, tenants, deliveries, sessions and signing keys,
// must belong to this invocation. Separate stores may reuse fixture names;
// merely creating a new organization in a shared delivery store is insufficient.
// Wire clock.Now into the real host's issuance and verification configuration.
// Do not use t.Setenv, package singletons or parent-scoped deferred cleanup.
type Factory func(t *testing.T, clock *Clock) (grpc.ClientConnInterface, []byte, Fixture)

// RunParallel runs every Run scenario with its own host and controlled clock.
// Nested assertions of a stateful scenario remain ordered within that scenario.
// Go's -parallel flag bounds concurrent fixtures, including their setup/cleanup.
func RunParallel(t *testing.T, factory Factory) {
	t.Helper()
	if factory == nil {
		t.Fatal("conformance: an isolated host factory is required")
	}
	run(t, &client{factory: factory}, Fixture{})
}

func (c *client) run(t *testing.T, f Fixture, name string, check func(*testing.T, *client, Fixture)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		if c.factory != nil {
			t.Parallel()
			clock := NewClock(time.Now().UTC())
			conn, descriptors, fixture := c.factory(t, clock)
			isolated, err := newClient(conn, descriptors)
			if err != nil {
				t.Fatalf("conformance: %v", err)
			}
			fixture.Clock = clock
			check(t, isolated, fixture)
			return
		}
		check(t, c, f)
	})
}

// atHostTime keeps Run compatible with live hosts that cannot inject a clock.
// RunParallel always supplies a Clock and never takes the wall-clock path.
func atHostTime(t *testing.T, f Fixture, now, at time.Time) {
	t.Helper()
	if f.Clock == nil {
		time.Sleep(at.Sub(now))
		return
	}
	before := f.Clock.Now()
	t.Cleanup(func() { f.Clock.Set(before) })
	f.Clock.Set(at)
}
