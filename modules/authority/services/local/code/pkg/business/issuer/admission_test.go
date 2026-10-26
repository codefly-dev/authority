package issuer_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/authority/libraries/authority-client/go/stamp"
	"github.com/codefly-dev/authority/libraries/authority-core/go/domain"

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
	id, public := hop.Admission()
	key, until, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public)
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
	_, public := hopSigner(t, "impostor").Admission()
	_, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.Credential(t, "documents"), public)
	if code, _ := domain.CodeOf(err); code != domain.Denied || !strings.Contains(err.Error(), "the caller is documents/documents, not the hop (authority/hop)") {
		t.Fatalf("a module registered an admission key: %v", err)
	}
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), "not-a-credential", public); !errors.Is(err, state.ErrForbidden) {
		t.Fatalf("an unattested caller registered an admission key: %v", err)
	}
	if ids := published(k); len(ids) != 0 {
		t.Fatalf("a refused registration published %v", ids)
	}
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public[:16]); err == nil {
		t.Fatal("a truncated key was registered")
	}
}

// A hop that restarts registers the same key again: one entry, renewed, never
// a second one.
func TestReRegistrationAtRestartIsIdempotent(t *testing.T) {
	k := testkit.Bare(t)
	clock := time.Now()
	issuer.SetClock(k.Issuer, func() time.Time { return clock })
	_, public := hopSigner(t, "the-hop").Admission()
	_, first, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(issuer.AdmissionLease / 2)
	_, renewed, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public)
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
	retiringID, retiring := hopSigner(t, "retiring").Admission()
	nextID, next := hopSigner(t, "next").Admission()
	for _, public := range [][]byte{retiring, next} {
		if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public); err != nil {
			t.Fatal(err)
		}
	}
	if ids := published(k); len(ids) != 2 {
		t.Fatalf("the overlap publishes %v", ids)
	}
	// Only the new key's hops still run and renew.
	for range 3 {
		clock = clock.Add(issuer.AdmissionLease / 2)
		if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), next); err != nil {
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
	var last []byte
	for n := 0; ; n++ {
		_, public := hopSigner(t, "key-"+string(rune('a'+n))).Admission()
		_, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), public)
		if err == nil {
			last = public
			continue
		}
		if code, _ := domain.CodeOf(err); code != domain.Precondition || !strings.Contains(err.Error(), "already published") || n < 2 {
			t.Fatalf("key %d: %v", n, err)
		}
		break
	}
	if _, _, err := k.Issuer.RegisterAdmissionKey(t.Context(), k.HopCredential(t), last); err != nil {
		t.Fatalf("a registered key no longer renews at the bound: %v", err)
	}
}
