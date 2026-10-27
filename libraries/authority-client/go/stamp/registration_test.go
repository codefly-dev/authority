package stamp

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

// Review #28 F1: a registration proves possession of the admission key. The
// key itself signs the credential it is presented with, the key and the
// authority's audience, fresh; a proof for anything else is refused.
func TestARegistrationProofBindsCredentialKeyAudienceAndTime(t *testing.T) {
	hop, err := NewSigner(strings.Repeat("02", 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewSigner(strings.Repeat("03", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, public := hop.Admission()
	_, otherPublic := other.Admission()
	now := time.Unix(1700000000, 0)
	const credential, audience = "hop-credential", "https://authority.test"
	proof, err := hop.ProveRegistration(credential, audience, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CheckRegistration(proof, public, credential, audience, now)
	if err != nil || got.Issued != now.Unix() || len(got.Nonce) != 64 {
		t.Fatalf("a fresh proof by the key was refused: %+v %v", got, err)
	}
	again, _ := hop.ProveRegistration(credential, audience, now)
	if second, _ := CheckRegistration(again, public, credential, audience, now); second.Nonce == got.Nonce {
		t.Fatal("two proofs share a nonce")
	}
	forged, _ := other.ProveRegistration(credential, audience, now)
	payload, signature, _ := strings.Cut(proof, ".")
	_, otherSignature, _ := strings.Cut(forged, ".")
	for name, tc := range map[string]struct {
		proof, credential, audience string
		public                      ed25519.PublicKey
		now                         time.Time
		want                        string
	}{
		"none":                  {"", credential, audience, public, now, "missing"},
		"another key's proof":   {forged, credential, audience, public, now, "not signed by the key being registered"},
		"a key without its own": {proof, credential, audience, otherPublic, now, "not signed by the key being registered"},
		"spliced signature":     {payload + "." + otherSignature, credential, audience, public, now, "not signed by the key being registered"},
		"padded signature":      {payload + "." + signature + "=", credential, audience, public, now, "not canonical"},
		"another credential":    {proof, "stolen-credential", audience, public, now, "another workload credential"},
		"another authority":     {proof, credential, "https://elsewhere.test", public, now, "another authority"},
		"stale":                 {proof, credential, audience, public, now.Add(RegistrationWindow), "stale"},
		"ahead of the clock":    {proof, credential, audience, public, now.Add(-Skew - time.Second), "ahead"},
	} {
		if _, err := CheckRegistration(tc.proof, tc.public, tc.credential, tc.audience, tc.now); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if _, err := CheckRegistration(proof, public, credential, audience, now.Add(RegistrationWindow-time.Second)); err != nil {
		t.Fatalf("a proof inside its window was refused: %v", err)
	}
	// A call admission is never a registration proof, though the same key signs both.
	call, err := hop.Sign("token", "/pkg.Service/Read", "module", now, now.Add(time.Minute).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckRegistration(call, public, credential, audience, now); err == nil {
		t.Fatal("a call admission was accepted as a registration proof")
	}
	if _, err := hop.ProveRegistration("", audience, now); err == nil {
		t.Fatal("a proof without a credential was signed")
	}
}
