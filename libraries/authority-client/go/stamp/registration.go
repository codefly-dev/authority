package stamp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// RegistrationWindow is how long a registration proof stays fresh: an
// authority refuses one signed longer ago than this, or more than Skew ahead
// of its clock, and remembers each nonce it accepted for this window plus Skew.
const RegistrationWindow = 30 * time.Second

// registrationDomain separates a registration proof from a call admission
// ("codefly-hop-v1") and from a Work Context: a signature for one is never
// read as the other.
const registrationDomain = "codefly-hop-registration-v1"

// Registration is a checked registration proof: who it binds and when it was
// signed. The nonce is what an authority reserves so the proof is used once.
type Registration struct {
	Nonce  string
	Issued int64
}

// ProveRegistration is the hop's proof that it holds the admission key it
// registers: the admission key itself signs the authority's audience, the
// digest of the workload credential presented with it, the public key and a
// fresh nonce and time. A captured credential alone therefore registers
// nothing, and a proof made for one credential, key or authority is refused
// with any other.
func (s *Signer) ProveRegistration(credential, audience string, now time.Time) (string, error) {
	if s == nil || len(s.key) != ed25519.PrivateKeySize || credential == "" || audience == "" {
		return "", errors.New("hop: a registration proof needs the admission key, the workload credential and the authority's audience")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", errors.New("hop: cannot generate a registration nonce")
	}
	_, public := s.Admission()
	payload, err := registrationPayload(audience, credential, public, hex.EncodeToString(nonce), now.Unix())
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, payload)), nil
}

func registrationPayload(audience, credential string, public []byte, nonce string, issued int64) ([]byte, error) {
	digest := sha256.Sum256([]byte(credential))
	return json.Marshal([]any{registrationDomain, audience, hex.EncodeToString(digest[:]), hex.EncodeToString(public), nonce, issued})
}

// CheckRegistration verifies proof as the authority at audience: signed by
// public over exactly this credential, this key and this audience, within
// RegistrationWindow of now. It does not remember the nonce; the caller
// reserves it, once every other check has passed.
func CheckRegistration(proof string, public ed25519.PublicKey, credential, audience string, now time.Time) (Registration, error) {
	refuse := func(why string) (Registration, error) {
		return Registration{}, errors.New("the registration proof " + why)
	}
	if len(proof) > 4096 {
		return refuse("is too long")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 2 {
		return refuse("is missing or not <payload>.<signature>: the hop proves it holds the key it registers")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != parts[0] {
		return refuse("payload is not canonical base64url")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != parts[1] {
		return refuse("signature is not canonical base64url")
	}
	if len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, payload, signature) {
		return refuse("is not signed by the key being registered")
	}
	var fields []json.RawMessage
	if json.Unmarshal(payload, &fields) != nil || len(fields) != 6 {
		return refuse("payload is not the registration array")
	}
	var domain, signedAudience, digest, key string
	var got Registration
	for n, dst := range []any{&domain, &signedAudience, &digest, &key, &got.Nonce, &got.Issued} {
		if string(fields[n]) == "null" || json.Unmarshal(fields[n], dst) != nil {
			return refuse("payload is not the registration array")
		}
	}
	want := sha256.Sum256([]byte(credential))
	nonce, err := hex.DecodeString(got.Nonce)
	switch {
	case domain != registrationDomain:
		return refuse("is not a registration proof")
	case audience == "" || signedAudience != audience:
		return refuse("is for another authority")
	case digest != hex.EncodeToString(want[:]):
		return refuse("was made for another workload credential")
	case key != hex.EncodeToString(public):
		return refuse("names another key")
	case err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != got.Nonce:
		return refuse("carries no 32-byte nonce")
	case got.Issued > now.Add(Skew).Unix():
		return refuse("is signed ahead of the authority's clock")
	case got.Issued <= now.Add(-RegistrationWindow).Unix():
		return refuse("is stale: sign a fresh one for each registration")
	}
	return got, nil
}
