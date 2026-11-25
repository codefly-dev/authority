package authority_test

import (
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

func TestChildDeadlineDoesNotSlideWhileIssuanceReadsState(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	ledgerWithRoles(t, h, "rob")
	parent := h.must(h.root("rob", "ledger", sc(ledgerKind, "read")))
	deadline := time.Unix(parent.Context.GetExpiresAtUnix(), 0)
	h.now = deadline.Add(-time.Minute)
	// Every clock read advances time, exposing conversion of an absolute
	// parent deadline to a duration later added to another clock reading.
	cfg := h.cfg
	cfg.Clock = func() time.Time {
		now := h.now
		h.now = h.now.Add(time.Second)
		return now
	}
	svc, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	child, err := svc.IssueChild(h.ctx, parent.Token, authority.Workload{Module: "ledger"}, authority.IssueRequest{Binding: "self"})
	if err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(child.Context.GetExpiresAtUnix(), 0); got.After(deadline) {
		t.Fatalf("child expires at %s after parent deadline %s", got, deadline)
	}
}
