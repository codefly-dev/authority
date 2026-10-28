package authority_test

import (
	"crypto"
	"io"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/workcontext"
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

// A refresh close to the delegation's end must not buy another MaxTTL of
// access. The signed expiry, not just OAuth's expires_in, carries the bound.
// Core verification still applies its documented clock-skew tolerance.
func TestDelegatedCapabilitiesDoNotOutliveTheirDelegation(t *testing.T) {
	for _, requested := range []time.Duration{0, time.Hour, 10 * time.Second} {
		t.Run(requested.String(), func(t *testing.T) {
			h := newHarness(t)
			h.grant("a", "viewer", "maya")
			d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a",
				[]*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read"})}, "one bounded run", 60)
			if err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(30 * time.Second)
			out := h.must(h.svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store", TTL: requested}))
			want := d.ExpiresAt.Unix()
			if requested == 10*time.Second {
				want = h.now.Add(requested).Unix()
			}
			if got := out.Context.GetExpiresAtUnix(); got != want {
				t.Fatalf("capability expires at %d, want %d (delegation ends %v)", got, want, d.ExpiresAt)
			}
			if err := h.check(out); err != nil {
				t.Fatal(err)
			}
			h.now = d.ExpiresAt.Add(workcontext.DefaultSkew)
			if err := h.check(out); err == nil {
				t.Fatal("a capability still admits work past its delegation's end and verifier clock tolerance")
			}
		})
	}
}

type changeAfterSigning struct {
	crypto.Signer
	change func()
}

func (s *changeAfterSigning) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signed, err := s.Signer.Sign(random, digest, opts)
	if err == nil && s.change != nil {
		change := s.change
		s.change = nil
		change()
	}
	return signed, err
}

func TestDelegationEndIsRereadAfterSigning(t *testing.T) {
	h := newHarness(t)
	h.grant("a", "viewer", "maya")
	d, err := h.svc.Delegate(h.ctx, h.person("maya"), "a",
		[]*basev0.WorkScopeV1{owned(kind, h.principal(acme, "a"), []string{"read"})}, "one bounded run", 60)
	if err != nil {
		t.Fatal(err)
	}
	h.cfg.Signer = &changeAfterSigning{Signer: h.cfg.Signer, change: func() {
		d.ExpiresAt = h.now.Add(30 * time.Second)
		if err := h.store.Write(h.ctx, func(tx authority.Tx) error { return tx.PutDelegation(d) }); err != nil {
			t.Fatal(err)
		}
	}}
	svc, err := authority.New(h.store, h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store"})
	code(t, err, domain.Denied)
	refused(t, err, "outlive")
}
