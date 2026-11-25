package authority_test

import (
	"testing"

	"github.com/codefly-dev/authority/libraries/authority-core/go/authority"
)

// An advisory check answers a refused method with the verified capability
// and the refusal beside it. That is advice for a development run, and a host
// serves it only by saying so (Config.Advisory). A host that does not say so
// enforces an advisory check as any other: the method's refusal is the
// answer, and no capability comes back with it.
func TestAnAdvisoryCheckIsEnforcedUnlessTheHostServesAdvice(t *testing.T) {
	t.Parallel()
	h := reachHarness(t)
	at := h.must(h.through("maya", "a", "store"))
	verified, _, refusal, err := h.svc.CheckMethod(h.ctx, at.Token, "store", storePurge, true)
	if err == nil || refusal != nil || verified != nil {
		t.Fatalf("a host that serves no advice answered an advisory check of a refused method with the capability: verified %v, refusal %v, error %v", verified != nil, refusal, err)
	}
	refused(t, err, "requires "+kind+":admin")
	if _, _, refusal, err := h.svc.CheckMethod(h.ctx, at.Token, "store", storeRead, true); err != nil || refusal != nil {
		t.Fatalf("an admitted method asked as advice: refusal %v, error %v", refusal, err)
	}

	cfg := h.cfg
	cfg.Advisory = true
	advising, err := authority.New(h.store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	verified, _, refusal, err = advising.CheckMethod(h.ctx, at.Token, "store", storePurge, true)
	if err != nil || verified == nil {
		t.Fatalf("a host that serves advice: %v", err)
	}
	refused(t, refusal, "requires "+kind+":admin")
}
