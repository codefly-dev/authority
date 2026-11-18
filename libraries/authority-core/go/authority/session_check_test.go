package authority_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

func TestSessionLedgerFailureRefusesIssueVerifyAndChild(t *testing.T) {
	h := newHarness(t)
	ledgerWithRoles(t, h, "rob")
	cfg := h.cfg
	var failure error
	var seen []string
	cfg.CheckSession = func(_ context.Context, id string) error { seen = append(seen, id); return failure }
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	person := h.person("rob")
	person.SessionID = "interactive-root"
	root, err := svc.IssueForPerson(h.ctx, person, authority.IssueRequest{Audience: "ledger"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range seen {
		if id != person.SessionID {
			t.Fatalf("checked %q instead of root %q", id, person.SessionID)
		}
	}
	if len(seen) == 0 {
		t.Fatal("session ledger not consulted")
	}
	failure = errors.New("session ledger unavailable or session ended")
	if _, err := svc.Verify(h.ctx, root.Token, root.Context.GetAudience()); !errors.Is(err, failure) {
		t.Fatalf("root verification: %v", err)
	}
	if _, err := svc.Verify(h.ctx, child.Token, child.Context.GetAudience()); !errors.Is(err, failure) {
		t.Fatalf("child verification: %v", err)
	}
	if out, err := svc.IssueForPerson(h.ctx, person, authority.IssueRequest{Audience: "ledger"}); !errors.Is(err, failure) || out.Token != "" {
		t.Fatalf("root issue returned token=%t err=%v", out.Token != "", err)
	}
	if out, err := svc.IssueChild(h.ctx, root.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self"}); !errors.Is(err, failure) || out.Token != "" {
		t.Fatalf("child issue returned token=%t err=%v", out.Token != "", err)
	}
}

// Hold issuance after its session lookup has observed the live session. Ending
// the session in that window must fence even a token signed after sign-out.
func TestSignOutDuringPersonIssuance(t *testing.T) {
	h := newHarness(t)
	ledgerWithRoles(t, h, "rob")
	var ended atomic.Bool
	checked := make(chan struct{})
	resume := make(chan struct{})
	expired := errors.New("session ended")
	cfg := h.cfg
	cfg.CheckSession = func(context.Context, string) error {
		if ended.Load() {
			return expired
		}
		close(checked)
		<-resume
		return nil
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	person := h.person("rob")
	person.SessionID = "interactive-root"
	type result struct {
		token string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		out, err := svc.IssueForPerson(h.ctx, person, authority.IssueRequest{Audience: "ledger"})
		done <- result{out.Token, err}
	}()
	select {
	case <-checked:
	case r := <-done:
		t.Fatalf("issuance finished before checking the session: %v", r.err)
	}
	ended.Store(true)
	close(resume)
	r := <-done
	if r.err != nil {
		if !errors.Is(r.err, expired) || r.token != "" {
			t.Fatalf("unexpected issuance result: token=%t err=%v", r.token != "", r.err)
		}
		return
	}
	if r.token == "" {
		t.Fatal("successful issue returned an empty token")
	}
	if _, err := svc.Verify(h.ctx, r.token, "ledger"); !errors.Is(err, expired) {
		t.Fatalf("verification after sign-out: %v", err)
	}
}
