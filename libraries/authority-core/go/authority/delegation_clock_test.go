package authority_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"
)

// A real store can take time reading the mint's revision and seal after the
// delegation decision. Advance the injected clock there, without sleeps.
type mintDelayStore struct {
	authority.Store
	advance func()
}

type mintDelayTx struct {
	authority.Tx
	store *mintDelayStore
}

func (s *mintDelayStore) Read(ctx context.Context, fn func(authority.Tx) error) error {
	return s.Store.Read(ctx, func(tx authority.Tx) error { return fn(mintDelayTx{tx, s}) })
}

func (tx mintDelayTx) AuthorizationRevision(org string) (uint64, error) {
	if advance := tx.store.advance; advance != nil {
		tx.store.advance = nil
		advance()
	}
	return tx.Tx.AuthorizationRevision(org)
}

func TestDelegationDeadlineSurvivesMintReadLatency(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, delay := range []time.Duration{0, 100 * time.Millisecond, 1500 * time.Millisecond, 61 * time.Second} {
			for _, requested := range []time.Duration{0, 10 * time.Second} {
				t.Run(fmt.Sprintf("client=%t/delay=%s/ttl=%s", client, delay, requested), func(t *testing.T) {
					h := newHarness(t)
					h.now = h.now.Add(950 * time.Millisecond)
					h.grant("a", "viewer", "maya")
					scopes := authority.Scopes{owned(kind, h.principal(acme, "a"), read)}
					var d domain.Delegation
					var err error
					if client {
						c, err := h.svc.RegisterClient(h.ctx, "External client", []string{"https://client.invalid/callback"})
						if err != nil {
							t.Fatal(err)
						}
						d, err = h.svc.DelegateToClient(h.ctx, h.person("maya"), c.ID, "a", h.cfg.Issuer+"/mcp/a", scopes, "bounded run", 60)
					} else {
						d, err = h.svc.Delegate(h.ctx, h.person("maya"), "a", scopes, "bounded run", 60)
					}
					if err != nil {
						t.Fatal(err)
					}
					started := h.now
					store := &mintDelayStore{Store: h.store}
					newID := h.cfg.NewID
					advanced := false
					// The task ID is requested after the grant decision and before
					// Core.Start reads its revision. Earlier decision reads stay live.
					h.cfg.NewID = func() string {
						store.advance = func() { h.now = h.now.Add(delay); advanced = true }
						return newID()
					}
					svc, err := authority.New(store, h.cfg)
					if err != nil {
						t.Fatal(err)
					}
					var out authority.Issued
					if client {
						out, err = svc.IssueForClientDelegation(h.ctx, d.ID, d.ClientID, d.Resource, authority.IssueRequest{TTL: requested})
					} else {
						out, err = svc.IssueForDelegation(h.ctx, d.ID, authority.Workload{Module: "a"}, authority.IssueRequest{Binding: "store", TTL: requested})
					}
					if !advanced {
						t.Fatal("test did not reach the mint revision read")
					}
					if delay >= time.Minute {
						if err == nil || out.Token != "" {
							t.Fatal("issuance returned authority after the delegation expired during minting")
						}
						return
					}
					if err != nil {
						t.Fatalf("a live delegation should issue despite mint read latency: %v", err)
					}
					want := d.ExpiresAt.Unix()
					if requested > 0 {
						want = started.Add(requested).Unix()
					}
					if got := out.Context.GetExpiresAtUnix(); got != want {
						t.Fatalf("signed expiry = %d, want %d; mint latency must not extend the window", got, want)
					}
					if err := h.check(out); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}
