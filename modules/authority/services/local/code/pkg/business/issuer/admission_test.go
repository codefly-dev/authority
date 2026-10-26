package issuer_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"

	authorityv1 "gateway/pkg/gen/host/authority/v1"

	"gateway/pkg/business/issuer"
	"gateway/pkg/business/state"
	"gateway/pkg/business/testkit"
)

func hopSigner(t *testing.T, label string) *stamp.Signer {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	signer, err := stamp.NewSigner(hex.EncodeToString(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// register registers signer's admission key as the hop presenting credential
// would at at: with a fresh proof signed by that key.
func register(t *testing.T, k *testkit.Kit, signer *stamp.Signer, credential string, at time.Time) (*authorityv1.PublicKey, time.Time, error) {
	t.Helper()
	proof, err := signer.ProveRegistration(credential, testkit.Audience, at)
	if err != nil {
		t.Fatal(err)
	}
	_, public := signer.Admission()
	return k.Issuer.RegisterAdmissionKey(t.Context(), credential, public, proof)
}

func published(k *testkit.Kit) []string {
	var ids []string
	for _, key := range k.Issuer.Keys().GetAdmissionKeys() {
		ids = append(ids, key.GetKeyId())
	}
	return ids
}

// Review r4 B1': the hop registers its admission key with the authority under
// its own workload credential, and Keys publishes exactly that public key, as
// an admission key and never a Work Context key. Nothing about the hop is
// configured on the authority.
func TestTheHopsRegisteredKeyIsPublishedInKeys(t *testing.T) {
	k := testkit.Bare(t)
	if keys := k.Issuer.Keys().GetAdmissionKeys(); len(keys) != 0 {
		t.Fatalf("an authority no hop registered with publishes %v", keys)
	}
	hop := hopSigner(t, "the-hop")
	id, _ := hop.Admission()
	key, until, err := register(t, k, hop, k.HopCredential(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if key.GetKeyId() != id || key.GetPurpose() != stamp.Purpose || key.GetAlgorithm() != "Ed25519" || hex.EncodeToString(key.GetPublicKey()) != hop.PublicKey() {
		t.Fatalf("registered %v, not the hop's public key", key)
	}
	if lease := time.Until(until); lease <= 0 || lease > issuer.AdmissionLease {
		t.Fatalf("the registration lapses in %s", lease)
	}
	keys := k.Issuer.Keys()
	if got := keys.GetAdmissionKeys(); len(got) != 1 || got[0].GetKeyId() != id {
		t.Fatalf("Keys publishes %v", got)
	}
	for _, workContextKey := range keys.GetKeys() {
		if workContextKey.GetKeyId() == id {
			t.Fatal("the hop's admission key is published as a Work Context key")
		}
	}
}

// Only the hop registers an admission key: another composed workload is
// refused by name, and so is a credential the launcher did not sign.
func TestANonHopCallerIsRefusedByName(t *testing.T) {
	k := testkit.Bare(t)
	impostor := hopSigner(t, "impostor")
	_, public := impostor.Admission()
	_, _, err := register(t, k, impostor, k.Credential(t, "documents"), time.Now())
	if code, _ := domain.CodeOf(err); code != domain.Denied || !strings.Contains(err.Error(), "the caller is documents/documents, not the hop (authority/hop)") {
		t.Fatalf("a module registered an admission key: %v", err)
	}
	if _, _, err := register(t, k, impostor, "not-a-credential", time.Now()); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("an unattested caller registered an admission key: %v", err)
	}
	if ids := published(k); len(ids) != 0 {
		t.Fatalf("a refused registration published %v", ids)
	}
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public[:16], ""); err == nil {
		t.Fatal("a truncated key was registered")
	}
}

// A hop that restarts registers the same key again: one entry, renewed, never
// a second one.
func TestReRegistrationAtRestartIsIdempotent(t *testing.T) {
	k := testkit.Bare(t)
	clock := time.Now()
	issuer.SetClock(k.Issuer, func() time.Time { return clock })
	hop := hopSigner(t, "the-hop")
	_, first, err := register(t, k, hop, k.HopCredential(t), clock)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(issuer.AdmissionLease / 2)
	_, renewed, err := register(t, k, hop, k.HopCredential(t), clock)
	if err != nil || !renewed.After(first) {
		t.Fatalf("the restart renewed to %s (was %s): %v", renewed, first, err)
	}
	clock = first.Add(time.Second) // the first lease alone would have lapsed
	if ids := published(k); len(ids) != 1 {
		t.Fatalf("Keys publishes %v after a re-registration", ids)
	}
}

// A rotation overlaps: while the retiring and the new key are both
// registered, both are published; once no hop renews the retiring key its
// lease lapses and it is withdrawn, and the new key stays.
func TestARotationOverlapsUntilTheRetiringKeyLapses(t *testing.T) {
	k := testkit.Bare(t)
	clock := time.Now()
	issuer.SetClock(k.Issuer, func() time.Time { return clock })
	retiring, next := hopSigner(t, "retiring"), hopSigner(t, "next")
	retiringID, _ := retiring.Admission()
	nextID, _ := next.Admission()
	// The retiring key's hop and the new key's hop are two instances.
	if _, _, err := register(t, k, retiring, k.HopInstanceCredential(t, "hop-retiring"), clock); err != nil {
		t.Fatal(err)
	}
	if _, _, err := register(t, k, next, k.HopInstanceCredential(t, "hop-next"), clock); err != nil {
		t.Fatal(err)
	}
	if ids := published(k); len(ids) != 2 {
		t.Fatalf("the overlap publishes %v", ids)
	}
	// Only the new key's hops still run and renew.
	for range 3 {
		clock = clock.Add(issuer.AdmissionLease / 2)
		if _, _, err := register(t, k, next, k.HopInstanceCredential(t, "hop-next"), clock); err != nil {
			t.Fatal(err)
		}
	}
	if ids := published(k); len(ids) != 1 || ids[0] != nextID {
		t.Fatalf("after the overlap Keys publishes %v, want only %s (withdrawn: %s)", ids, nextID, retiringID)
	}
	clock = clock.Add(issuer.AdmissionLease)
	if ids := published(k); len(ids) != 0 {
		t.Fatalf("a key no hop renews is still published: %v", ids)
	}
}

// The published set is bounded: past it a new key waits for one to lapse,
// refused by name, while a registered key still renews.
func TestThePublishedAdmissionKeysAreBounded(t *testing.T) {
	k := testkit.Bare(t)
	var last *stamp.Signer
	var lastInstance string
	for n := 0; ; n++ {
		signer := hopSigner(t, "key-"+string(rune('a'+n)))
		_, _, err := register(t, k, signer, k.HopInstanceCredential(t, "hop-"+string(rune('a'+n))), time.Now())
		if err == nil {
			last, lastInstance = signer, "hop-"+string(rune('a'+n))
			continue
		}
		if code, _ := domain.CodeOf(err); code != domain.Precondition || !strings.Contains(err.Error(), "already published") || n < 2 {
			t.Fatalf("key %d: %v", n, err)
		}
		break
	}
	if _, _, err := register(t, k, last, k.HopInstanceCredential(t, lastInstance), time.Now()); err != nil {
		t.Fatalf("a registered key no longer renews at the bound: %v", err)
	}
}

// Review #28 F1: a registration carries a proof signed by the key it
// registers, bound to its credential and this authority, fresh and single
// use. No proof, a proof by another key, one made for another credential or
// authority, a stale one or a replayed one, registers nothing. (A proof by a
// key the registrant chose proves only possession of that key; the pin per
// hop instance, below, is what refuses a thief's own key.)
func TestARegistrationMustProveItHoldsTheKey(t *testing.T) {
	k := testkit.Bare(t)
	clock := time.Now()
	issuer.SetClock(k.Issuer, func() time.Time { return clock })
	hop, thief := hopSigner(t, "the-hop"), hopSigner(t, "thief")
	_, public := hop.Admission()
	_, thiefPublic := thief.Admission()
	credential := k.HopCredential(t)
	proof := func(signer *stamp.Signer, credential, audience string, at time.Time) string {
		p, err := signer.ProveRegistration(credential, audience, at)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, tc := range map[string]struct {
		public []byte
		proof  string
		want   string
	}{
		"no proof":                       {thiefPublic, "", "missing"},
		"the hop's proof, another key":   {thiefPublic, proof(hop, credential, testkit.Audience, clock), "not signed by the key being registered"},
		"a proof for another credential": {public, proof(hop, k.HopCredential(t), testkit.Audience, clock), "another workload credential"},
		"a proof for another authority":  {public, proof(hop, credential, "https://elsewhere.test", clock), "another authority"},
		"a stale proof":                  {public, proof(hop, credential, testkit.Audience, clock.Add(-stamp.RegistrationWindow)), "stale"},
	} {
		_, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), credential, tc.public, tc.proof)
		if code, _ := domain.CodeOf(err); code != domain.Denied || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, tc.want)
		}
	}
	if ids := published(k); len(ids) != 0 {
		t.Fatalf("a registration without proof of the key published %v", ids)
	}
	fresh := proof(hop, credential, testkit.Audience, clock)
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), credential, public, fresh); err != nil {
		t.Fatal(err)
	}
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), credential, public, fresh); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("a replayed registration was accepted: %v", err)
	}
	// The nonce is remembered only as long as the proof could pass as fresh.
	clock = clock.Add(stamp.RegistrationWindow + stamp.Skew)
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), credential, public, fresh); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("a replay after the window was not refused as stale: %v", err)
	}
}

// Review #28 F2: the hop must be this host's, by trust domain as well as by
// module and service: a hop the anchor vouches for in another trust domain is
// refused by name.
func TestOnlyTheHopOfThisHostsTrustDomainRegisters(t *testing.T) {
	k := testkit.Bare(t)
	if got := k.State.TrustDomain(); got != testkit.HopWorkload().TrustDomain {
		t.Fatalf("the host's trust domain is %q, not the run's %q", got, testkit.HopWorkload().TrustDomain)
	}
	hop := hopSigner(t, "the-hop")
	issuer.SetTrustDomain(k.Issuer, "elsewhere.test")
	_, _, err := register(t, k, hop, k.HopCredential(t), time.Now())
	if code, _ := domain.CodeOf(err); code != domain.Denied || !strings.Contains(err.Error(), `trust domain "local.test", not of this host's ("elsewhere.test")`) {
		t.Fatalf("a hop of another trust domain registered: %v", err)
	}
	issuer.SetTrustDomain(k.Issuer, "")
	if _, _, err := register(t, k, hop, k.HopCredential(t), time.Now()); err == nil {
		t.Fatal("a host that knows no trust domain of its own accepted a hop")
	}
	if ids := published(k); len(ids) != 0 {
		t.Fatalf("a hop of another trust domain published %v", ids)
	}
	issuer.SetTrustDomain(k.Issuer, k.State.TrustDomain())
	if _, _, err := register(t, k, hop, k.HopCredential(t), time.Now()); err != nil {
		t.Fatalf("this host's hop was refused: %v", err)
	}
}

// Review #32 B1: the proof alone does not stop a thief with the hop's
// credential, who signs with a key of its own. One key is pinned per hop
// instance: once the hop has registered, a different key under that
// instance's credential is refused by name, even with a valid fresh proof;
// the hop's own key keeps renewing; a new instance (a restarted or rotated
// hop) registers its key; and once an instance's lease lapses its pin is
// released.
func TestAHopInstanceHoldsOneAdmissionKey(t *testing.T) {
	k := testkit.Bare(t)
	clock := time.Now()
	issuer.SetClock(k.Issuer, func() time.Time { return clock })
	hop, thief := hopSigner(t, "the-hop"), hopSigner(t, "thief")
	hopID, _ := hop.Admission()
	thiefID, _ := thief.Admission()
	if _, _, err := register(t, k, hop, k.HopCredential(t), clock); err != nil {
		t.Fatal(err)
	}
	// The review's probe: the stolen credential, the thief's own key, a valid proof.
	stolen := k.HopCredential(t)
	_, _, err := register(t, k, thief, stolen, clock)
	if code, _ := domain.CodeOf(err); code != domain.Denied || !strings.Contains(err.Error(), `hop instance "hop-1" registered admission key `+hopID) || !strings.Contains(err.Error(), thiefID) {
		t.Fatalf("a thief's own key registered under the hop's credential: %v", err)
	}
	if ids := published(k); len(ids) != 1 || ids[0] != hopID {
		t.Fatalf("Keys publishes %v, want only the hop's %s", ids, hopID)
	}
	// The hop renews, under a re-issued credential of the same instance.
	clock = clock.Add(issuer.AdmissionLease / 2)
	if _, _, err := register(t, k, hop, k.HopCredential(t), clock); err != nil {
		t.Fatalf("the hop's renewal was refused: %v", err)
	}
	if _, _, err := register(t, k, thief, stolen, clock); err == nil {
		t.Fatal("a thief's key registered after the hop renewed")
	}
	// A restarted hop is a new instance: its key, the same or a new one, registers.
	restarted := hopSigner(t, "the-hop-after-restart")
	restartedID, _ := restarted.Admission()
	if _, _, err := register(t, k, restarted, k.HopInstanceCredential(t, "hop-2"), clock); err != nil {
		t.Fatalf("a new hop instance was refused: %v", err)
	}
	if _, _, err := register(t, k, hop, k.HopInstanceCredential(t, "hop-3"), clock); err != nil {
		t.Fatalf("a replica sharing the hop's key was refused: %v", err)
	}
	if ids := published(k); len(ids) != 2 || !slices.Contains(ids, hopID) || !slices.Contains(ids, restartedID) {
		t.Fatalf("Keys publishes %v", ids)
	}
	// Once hop-1 stops renewing and its lease lapses, its pin is released.
	clock = clock.Add(issuer.AdmissionLease)
	if _, _, err := register(t, k, thief, k.HopCredential(t), clock); err != nil {
		t.Fatalf("hop-1's pin outlived its lease: %v", err)
	}
}

// What the pin does not stop, said by a test so it is not mistaken for more:
// a captured credential that registers before its instance's own first
// registration pins the thief's key, and the hop's own registration is then
// refused by name, so the hop's log shows it.
func TestTheFirstRegistrationOfAnInstanceWins(t *testing.T) {
	k := testkit.Bare(t)
	hop, thief := hopSigner(t, "the-hop"), hopSigner(t, "thief")
	thiefID, _ := thief.Admission()
	if _, _, err := register(t, k, thief, k.HopCredential(t), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := register(t, k, hop, k.HopCredential(t), time.Now()); err == nil || !strings.Contains(err.Error(), "registered admission key "+thiefID) {
		t.Fatalf("the hop's registration after a first one by another key: %v", err)
	}
}
