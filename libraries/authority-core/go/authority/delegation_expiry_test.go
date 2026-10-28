package authority_test

import (
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
)

// A delegation asked for with a lifetime ends by itself (handbook proposal
// 2026-10-28-a-person-delegates-a-run-from-the-page): past it, nothing issues
// from it and its module reads it as ended. The lifetime is clamped to the
// host's ceiling; none asked keeps a delegation until it is revoked.
func TestADelegationWithALifetimeEndsByItself(t *testing.T) {
	// Maya views module a's own collection and delegates that read to a,
	// which issues through its "store" binding (as race_test does).
	setup := func(t *testing.T) (*harness, []*basev0.WorkScopeV1) {
		h := newHarness(t)
		h.grant("a", "viewer", "maya")
		return h, []*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read"})}
	}
	issue := func(h *harness, d domain.Delegation) error {
		_, err := h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
		return err
	}

	t.Run("it issues until it expires, then refuses", func(t *testing.T) {
		h, read := setup(t)
		d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", read, "a run", 3600)
		if err != nil {
			t.Fatal(err)
		}
		if want := h.now.Add(time.Hour); !d.ExpiresAt.Equal(want) {
			t.Fatalf("expires at %v, want %v", d.ExpiresAt, want)
		}
		if err := issue(h, d); err != nil {
			t.Fatalf("a standing delegation did not issue: %v", err)
		}
		h.now = h.now.Add(time.Hour)
		err = issue(h, d)
		code(t, err, domain.Denied)
		refused(t, err, "expired")
		got, err := h.svc.Delegation(h.ctx, d.ID, nil, &authority.Workload{Module: "a"})
		if err != nil || got.Active(h.now) {
			t.Fatalf("its module reads an expired delegation as standing: %+v %v", got, err)
		}
	})
	t.Run("a lifetime past the ceiling is clamped to it", func(t *testing.T) {
		h, read := setup(t)
		d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", read, "a run", 365*24*3600)
		if err != nil {
			t.Fatal(err)
		}
		if want := h.now.Add(authority.DefaultMaxDelegationTTL); !d.ExpiresAt.Equal(want) {
			t.Fatalf("expires at %v, want the ceiling %v", d.ExpiresAt, want)
		}
	})
	// Seconds that overflow a Duration once multiplied (2^55 s is 0 ns after
	// wrapping) are still a lifetime past the ceiling, or a negative one: never
	// a delegation that stands until revoked (review of #50).
	t.Run("a lifetime too large to convert is clamped, never unbounded", func(t *testing.T) {
		h, read := setup(t)
		d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", read, "a run", 1<<55)
		if err != nil {
			t.Fatal(err)
		}
		if want := h.now.Add(authority.DefaultMaxDelegationTTL); !d.ExpiresAt.Equal(want) {
			t.Fatalf("2^55 s expires at %v, want the ceiling %v", d.ExpiresAt, want)
		}
		_, err = h.svc.Delegate(h.ctx, h.person("maya"), "a", read, "a run", -(1 << 55))
		code(t, err, domain.Invalid)
	})
	t.Run("a negative lifetime is malformed", func(t *testing.T) {
		h, read := setup(t)
		_, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", read, "a run", -1)
		code(t, err, domain.Invalid)
	})
	t.Run("none asked stands until revoked", func(t *testing.T) {
		h, read := setup(t)
		d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a", read, "a job", 0)
		if err != nil {
			t.Fatal(err)
		}
		if !d.ExpiresAt.IsZero() {
			t.Fatalf("a delegation asked for with no lifetime expires at %v", d.ExpiresAt)
		}
		h.now = h.now.Add(365 * 24 * time.Hour)
		if err := issue(h, d); err != nil {
			t.Fatalf("a delegation with no lifetime stopped issuing: %v", err)
		}
	})
}
