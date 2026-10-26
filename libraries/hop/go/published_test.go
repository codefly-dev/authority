package hop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
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
// stamp_proof, and causes no read of the authority's keys: a caller cannot
// make the verifier re-read by presenting an unknown key.
func TestAStampSignedByAnUnpublishedKeyIsRefusedByName(t *testing.T) {
	authority := newSigner("published")
	source := &keys{response: &authorityv1.KeysResponse{Issuer: authority.issuer, Keys: []*authorityv1.PublicKey{authority.published()}}}
	v, _ := NewVerifier(context.Background(), source, "documents", core.NewMemoryReplayStore())
	settled(v)
	reads := source.count()
	_, err := v.Verify(context.Background(), forwarded(t, authority.issue(t, time.Now(), "documents"), "an-unpublished-hop", ""), "/test.Service/Read")
	var reason refusal.Reason
	if !errors.As(err, &reason) || reason != refusal.StampProof {
		t.Fatalf("want %s: %v", refusal.StampProof, err)
	}
	settled(v)
	if source.count() != reads {
		t.Fatalf("an unpublished key caused %d key reads", source.count()-reads)
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
