package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/refusal"
	core "github.com/codefly-dev/core/workcontext"
)

// Review r3 B1: the hop's admission key is published by the authority's Keys,
// which every verifier already reads, so nothing about the hop is configured
// on a module: a verifier built from Keys alone admits a genuine stamp.
func TestAVerifierTakesTheHopsKeyFromTheAuthoritysKeysAlone(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("the-hop")}}}
	v, err := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	id, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, time.Now(), "documents"), "the-hop", ""), "/test.Service/Read")
	if err != nil || id.Owner != core.FixturePrincipal {
		t.Fatalf("a genuine stamp under the published key: %+v %v", id, err)
	}
}

// A stamp signed by a key the authority does not publish is refused as
// stamp_proof after one re-read of the authority's keys, and a second such
// stamp inside signerRetry is refused on the keys held, reading nothing: a
// caller cannot make the verifier read more than once per signerRetry.
func TestAStampSignedByAnUnpublishedKeyIsRefusedByName(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()}}}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	clock := time.Now()
	v.now = func() time.Time { return clock }
	reads := source.count()
	var reason refusal.Reason
	for range 2 {
		_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "an-unpublished-hop", ""), "/test.Service/Read")
		if !errors.As(err, &reason) || reason != refusal.StampProof {
			t.Fatalf("want %s: %v", refusal.StampProof, err)
		}
		settled(v)
	}
	if source.count()-reads != 1 {
		t.Fatalf("two stamps under an unpublished key inside signerRetry caused %d key reads, want 1", source.count()-reads)
	}
}

// W7 (2026-11-09): the saas gateway registers a fresh admission key every time
// it starts and signs with it at once. A module that read the keys before the
// restart holds only the old key; the first stamp under the new one re-reads
// the published keys and is admitted, without waiting out keyMaxAge.
func TestARestartedHopsFreshKeyIsAdmittedWithoutWaitingKeyMaxAge(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("gateway-before-restart")}}}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	clock := time.Now()
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	// The gateway restarts and registers its fresh key; the old one is withdrawn.
	source.set(&authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("gateway-after-restart")}}, nil, nil)
	clock = clock.Add(time.Second) // far inside keyMaxAge and keyRetry
	reads := source.count()
	id, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "gateway-after-restart", ""), "/test.Service/Read")
	if err != nil || id.Owner != core.FixturePrincipal {
		t.Fatalf("the restarted gateway's first stamp: %+v %v", id, err)
	}
	if source.count()-reads != 1 {
		t.Fatalf("admitting the fresh key took %d key reads, want 1", source.count()-reads)
	}
	if _, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "gateway-after-restart", ""), "/test.Service/Read"); err != nil {
		t.Fatalf("the fresh key's next stamp: %v", err)
	}
	if source.count()-reads != 1 {
		t.Fatalf("a held key read the keys again: %d reads", source.count()-reads)
	}
}

// Review of #104: a restarted hop's first stamp can arrive while a read is
// already running — readiness, or keys past keyMaxAge. It waits for that read
// instead of being refused, and is admitted on what the read published.
// Waiting starts no read and spends no signerRetry: when the running read
// predates the registration, the next stamp under the fresh key starts its own.
func TestAStampUnderAnUnheldKeyWaitsForTheReadAlreadyRunning(t *testing.T) {
	authority := newSigner("published")
	publishing := func(labels ...string) *authorityv1.KeysResponse {
		response := &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()}}
		for _, label := range labels {
			response.AdmissionKeys = append(response.AdmissionKeys, publishedHop(label))
		}
		return response
	}
	source := &keys{response: publishing("gateway-before-restart")}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	clock := time.Now()
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	reads := source.count()
	// running starts a read through readiness, as a scheduled refresh does, and
	// holds it open until release; the read then answers response.
	running := func(response *authorityv1.KeysResponse) (release func()) {
		hold := make(chan struct{})
		source.set(response, nil, hold)
		clock = clock.Add(keyMaxAge + time.Second)
		v.Ready()
		return func() { close(hold) }
	}
	call := func(hop string) <-chan error {
		done := make(chan error, 1)
		go func() {
			_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), hop, ""), "/test.Service/Read")
			done <- err
		}()
		return done
	}
	waits := func(done <-chan error) {
		select {
		case err := <-done:
			t.Fatalf("a stamp under an unheld key was judged before the running read ended: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// The running read publishes the fresh key: the stamp waits, and is admitted.
	release := running(publishing("gateway-after-restart"))
	done := call("gateway-after-restart")
	waits(done)
	release()
	if err := <-done; err != nil {
		t.Fatalf("a restarted hop's stamp during a running read: %v", err)
	}
	settled(v)
	if source.count()-reads != 1 {
		t.Fatalf("waiting for the running read took %d key reads, want 1", source.count()-reads)
	}

	// The running read predates the next restart: the stamp waits and is
	// refused, and the next stamp under that key, inside signerRetry, still
	// starts its own read and is admitted.
	release = running(publishing("gateway-after-restart"))
	done = call("gateway-restarted-again")
	waits(done)
	release()
	var reason refusal.Reason
	if err := <-done; !errors.As(err, &reason) || reason != refusal.StampProof {
		t.Fatalf("a stamp the running read did not publish: want %s, got %v", refusal.StampProof, err)
	}
	settled(v)
	source.set(publishing("gateway-restarted-again"), nil, nil)
	if err := <-call("gateway-restarted-again"); err != nil {
		t.Fatalf("waiting spent signerRetry: the next stamp under the fresh key was refused: %v", err)
	}
	if source.count()-reads != 3 {
		t.Fatalf("two running reads and one started by a stamp took %d key reads, want 3", source.count()-reads)
	}
}

// A flood of stamps under keys nobody publishes costs the authority one read
// per signerRetry, whatever their number, and each is refused as stamp_proof.
func TestAFloodOfUnknownSignersCostsOneReadPerSignerRetry(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("the-hop")}}}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	start := time.Now()
	clock := start
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	token := authority.issue(t, clock, "documents")
	flood := func(n int) int {
		before := source.count()
		var reason refusal.Reason
		for i := range n {
			_, err := v.Verify(context.Background(), forwarded(t, token, fmt.Sprintf("forged-%d", i), ""), "/test.Service/Read")
			if !errors.As(err, &reason) || reason != refusal.StampProof {
				t.Fatalf("stamp %d under an unknown key: %v", i, err)
			}
		}
		settled(v)
		return source.count() - before
	}
	if reads := flood(200); reads != 1 {
		t.Fatalf("200 unknown signers drove %d key reads, want 1", reads)
	}
	clock = start.Add(signerRetry - time.Second)
	if reads := flood(50); reads != 0 {
		t.Fatalf("inside signerRetry, unknown signers drove %d key reads, want 0", reads)
	}
	clock = start.Add(signerRetry)
	if reads := flood(50); reads != 1 {
		t.Fatalf("after signerRetry, unknown signers drove %d key reads, want 1", reads)
	}
	// The genuine hop is never held up by the flood.
	if _, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "the-hop", ""), "/test.Service/Read"); err != nil {
		t.Fatalf("the genuine hop during the flood: %v", err)
	}
}

// While a hop's key rotates the authority publishes both, and the verifier
// admits stamps under either; once the retiring key is withdrawn, the next
// read stops admitting it.
func TestARotationsOverlapAdmitsBothKeysUntilTheRetiringOneIsWithdrawn(t *testing.T) {
	authority := newSigner("published")
	both := &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("retiring"), publishedHop("current")}}
	source := &keys{response: both}
	clock := time.Now()
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	v.now = func() time.Time { return clock }
	v.fetched, v.tried = clock, clock
	for _, hop := range []string{"retiring", "current"} {
		if _, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), hop, ""), "/test.Service/Read"); err != nil {
			t.Fatalf("the overlap refused the %s key: %v", hop, err)
		}
	}
	source.set(&authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("current")}}, nil, nil)
	clock = clock.Add(keyMaxAge + time.Second)
	v.Ready() // the periodic re-read
	settled(v)
	_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "retiring", ""), "/test.Service/Read")
	var reason refusal.Reason
	if !errors.As(err, &reason) || reason != refusal.StampProof {
		t.Fatalf("a withdrawn key still admits: %v", err)
	}
	if _, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "current", ""), "/test.Service/Read"); err != nil {
		t.Fatalf("the current key after the overlap: %v", err)
	}
}

// Each key is used for its own purpose only: an admission key published among
// the Work Context keys admits nothing, and an admission key never
// authenticates a Work Context.
func TestAKeyIsUsedForItsOwnPurposeOnly(t *testing.T) {
	authority := newSigner("published")
	misplaced := publishedHop("misplaced")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published(), misplaced}}}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	var reason refusal.Reason
	if _, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, time.Now(), "documents"), "misplaced", ""), "/test.Service/Read"); !errors.As(err, &reason) || reason != refusal.StampProof {
		t.Fatalf("an admission key among the Work Context keys admitted: %v", err)
	}
	// A Work Context signed with the hop's admission key (the keys double
	// publishes testSigner("proof")), under that entry's key id.
	seed := sha256.Sum256([]byte("proof"))
	forged := signer{id: publishedHop("proof").GetKeyId(), key: ed25519.NewKeyFromSeed(seed[:]), issuer: authority.issuer}
	if _, err := v.VerifyToken(context.Background(), forged.issue(t, time.Now(), "documents")); !errors.As(err, &reason) || reason != refusal.UnknownKey {
		t.Fatalf("a Work Context signed with the hop's admission key: %v", err)
	}
}

// An authority that publishes no admission key admits nothing, under a fixed
// reason, and says why in the module's logs.
func TestNoPublishedAdmissionKeyRefusesEveryCallAndSaysWhy(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{{Algorithm: core.Algorithm, PublicKey: make([]byte, 32), Purpose: "work-context"}}}}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, time.Now(), "documents"), "proof", ""), "/test.Service/Read")
	var reason refusal.Reason
	if !errors.As(err, &reason) || reason != refusal.KeysUnavailable {
		t.Fatalf("want %s: %v", refusal.KeysUnavailable, err)
	}
	if !errors.Is(v.KeysError(), ErrNoAdmissionKeys) {
		t.Fatalf("the module's logs are not told why: %v", v.KeysError())
	}
}

// Review r5: a verifier that first read Keys before the hop registered its
// key holds no admission key; once the authority publishes one, the next call
// or readiness check after keyRetry reads it, so the module admits a genuine
// stamp without waiting out keyMaxAge. Until then every call is refused as
// keys_unavailable, and an unknown caller drives at most one read per
// keyRetry.
func TestAVerifierThatReadBeforeTheHopRegisteredLearnsItsKeyWithinKeyRetry(t *testing.T) {
	authority := newSigner("published")
	// No admission key published (the double publishes one when the field is
	// empty, so it carries only an entry of another purpose, which is dropped).
	unregistered := func() *authorityv1.KeysResponse {
		return &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
			AdmissionKeys: []*authorityv1.PublicKey{{Algorithm: core.Algorithm, PublicKey: make([]byte, 32), Purpose: "work-context"}}}
	}
	source := &keys{response: unregistered()}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	clock := time.Now()
	v.now = func() time.Time { return clock }
	var reason refusal.Reason
	if _, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "the-hop", ""), "/test.Service/Read"); !errors.As(err, &reason) || reason != refusal.KeysUnavailable {
		t.Fatalf("before the hop registered: %v", err)
	}
	reads := source.count()
	for range 5 {
		_, _ = v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "the-hop", ""), "/test.Service/Read")
	}
	settled(v)
	if source.count() != reads {
		t.Fatalf("callers inside keyRetry drove %d key reads", source.count()-reads)
	}
	source.set(&authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()},
		AdmissionKeys: []*authorityv1.PublicKey{publishedHop("the-hop")}}, nil, nil)
	clock = clock.Add(keyRetry)
	if id, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, clock, "documents"), "the-hop", ""), "/test.Service/Read"); err != nil || id.Owner != core.FixturePrincipal {
		t.Fatalf("after the hop registered: %+v %v", id, err)
	}
	// Readiness reads too, for a replica that gets no call meanwhile.
	idle, _ := NewVerifier(context.Background(), &keys{response: unregistered()}, "documents", core.NewMemoryReplayStore())
	idle.now = func() time.Time { return clock }
	settled(idle)
	idle.source.(*keys).set(source.response, nil, nil)
	clock = clock.Add(keyRetry)
	idle.Ready()
	settled(idle)
	if idle.KeysError() != nil {
		t.Fatalf("readiness did not learn the registered key: %v", idle.KeysError())
	}
}
