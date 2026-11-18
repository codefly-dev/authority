package hop

import (
	"context"
	"errors"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	core "github.com/codefly-dev/core/workcontext"
)

// A hop admission key the authority has withdrawn stops admitting about
// admissionMaxAge later: a stamp arriving once the admission keys held are
// older than that starts a re-read, and once it lands the key admits nothing,
// with no readiness poll and no wait for keyMaxAge. Inside admissionMaxAge the
// held keys admit, reading nothing.
func TestAWithdrawnAdmissionKeyStopsAdmittingWithinAdmissionMaxAge(t *testing.T) {
	authority := newSigner("published")
	publishing := func(hops ...string) *authorityv1.KeysResponse {
		out := &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()}}
		for _, hop := range hops {
			out.AdmissionKeys = append(out.AdmissionKeys, publishedHop(hop))
		}
		return out
	}
	source := &keys{response: publishing("withdrawn", "current")}
	clock := time.Now()
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	admit := func(hop string) error {
		_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), hop, ""), "/test.Service/Read")
		settled(v)
		return err
	}
	for _, hop := range []string{"withdrawn", "current"} {
		if err := admit(hop); err != nil {
			t.Fatalf("the %s key while published: %v", hop, err)
		}
	}
	// The authority withdraws the key.
	source.set(publishing("current"), nil, nil)
	reads := source.count()
	clock = clock.Add(admissionMaxAge - time.Second)
	if err := admit("withdrawn"); err != nil || source.count() != reads {
		t.Fatalf("inside admissionMaxAge the held keys admit and nothing is read: %v, %d reads", err, source.count()-reads)
	}
	// Past admissionMaxAge a stamp starts the re-read; once it has landed
	// (admit waits for it) the withdrawn key admits nothing.
	clock = clock.Add(2 * time.Second)
	_ = admit("current")
	if source.count() != reads+1 {
		t.Fatalf("a stamp past admissionMaxAge started %d reads, want 1", source.count()-reads)
	}
	var reason refusal.Reason
	if err := admit("withdrawn"); !errors.As(err, &reason) || reason != refusal.StampProof {
		t.Fatalf("a key withdrawn %v ago still admits: %v", admissionMaxAge+time.Second, err)
	}
	if err := admit("current"); err != nil {
		t.Fatalf("the key still published: %v", err)
	}
	if admissionMaxAge > 30*time.Second {
		t.Fatalf("admissionMaxAge is %v: a withdrawal is honoured within seconds, not minutes", admissionMaxAge)
	}
}

// Admission keys the authority cannot confirm are trusted no longer than
// admissionStale: failed re-reads keep them that long, as a brief outage
// should, and then every stamp is refused as keys_unavailable. The Work
// Context keys keep their own, longer bound.
func TestAdmissionKeysTheAuthorityCannotConfirmAreTrustedNoLongerThanAdmissionStale(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("the-hop")}}}
	start := time.Now()
	clock := start
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	admit := func() error {
		_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "the-hop", ""), "/test.Service/Read")
		settled(v)
		return err
	}
	source.set(nil, errors.New("authority down"), nil)
	clock = start.Add(admissionMaxAge + time.Second)
	if err := admit(); err != nil {
		t.Fatalf("one failed re-read inside admissionStale took the key away: %v", err)
	}
	clock = start.Add(admissionStale + time.Second)
	var reason refusal.Reason
	if err := admit(); !errors.As(err, &reason) || reason != refusal.KeysUnavailable {
		t.Fatalf("an admission key unconfirmed for %v still admits: %v", admissionStale+time.Second, err)
	}
	// A call carrying no well-formed admission reads nothing and waits for
	// nothing, stale keys or not: it is refused for what it is.
	source.set(nil, errors.New("authority down"), nil)
	clock = clock.Add(keyRetry + time.Second)
	reads := source.count()
	garbage := forwarded(t, authority.issue(t, clock, "documents"), "the-hop", "")
	garbage.Set(ProofKey, "not-an-admission")
	if _, err := v.Verify(context.Background(), garbage, "/test.Service/Read"); !errors.As(err, &reason) || reason != refusal.StampProof || source.count() != reads {
		t.Fatalf("a malformed proof on stale admission keys: %v, %d reads", err, source.count()-reads)
	}
	if _, err := v.VerifyToken(context.Background(), authority.issue(t, clock, "documents")); err != nil {
		t.Fatalf("the Work Context keys inside keyStale: %v", err)
	}
	if admissionStale >= keyStale {
		t.Fatalf("admissionStale %v is no shorter than keyStale %v", admissionStale, keyStale)
	}
}
