package solutionhost_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

// These tests use real locally held keys and the offline verifier. The signing
// and DSSE verification implementation imports only the Go standard library.
type wireEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []wireSignature `json:"signatures"`
}

type wireSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

func signedWith(t *testing.T, payload []byte, signer solutionhost.Signer) *solutionhost.Signed {
	t.Helper()
	envelope, err := solutionhost.SignEnvelope(payload, signer)
	require.NoError(t, err)
	carrier, err := solutionhost.Carrier(payload, envelope)
	require.NoError(t, err)
	encoded, err := solutionhost.MarshalSigned(carrier)
	require.NoError(t, err)
	carrier, err = solutionhost.ParseSigned(encoded)
	require.NoError(t, err)
	return carrier
}

func changeEnvelope(t *testing.T, carrier *solutionhost.Signed, change func(*wireEnvelope)) *solutionhost.Signed {
	t.Helper()
	copy := *carrier
	var envelope wireEnvelope
	require.NoError(t, json.Unmarshal(carrier.Envelope, &envelope))
	change(&envelope)
	encoded, err := json.Marshal(&envelope)
	require.NoError(t, err)
	copy.Envelope = encoded
	return &copy
}

func TestPinnedKeysVerifyOffline(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256, err := solutionhost.NewInMemorySigner("local-person", ecdsaKey)
	require.NoError(t, err)
	for _, signer := range []*solutionhost.InMemorySigner{signerFor(t, testKeyID), p256} {
		for _, kind := range []solutionhost.KeyKind{solutionhost.KeyKindRelease, solutionhost.KeyKindPerson} {
			t.Run(signer.KeyID()+"/"+string(kind), func(t *testing.T) {
				verifier := verifierFor(t, pinFor(t, signer, kind, testDomain))
				payload, err := solutionhost.SignedPayload(valid(t))
				require.NoError(t, err)
				carrier := signedWith(t, payload, signer)
				delivered, err := solutionhost.VerifyDelivered(context.Background(), carrier, verifier)
				require.NoError(t, err)
				// An independently encoded PAE verifies, while a signature over
				// the bare document must fail for both supported algorithms.
				for _, usePAE := range []bool{true, false} {
					changed := changeEnvelope(t, carrier, func(e *wireEnvelope) {
						require.Equal(t, "application/vnd.codefly.module-manifest+json", e.PayloadType)
						message := payload
						if usePAE {
							message = []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(e.PayloadType), e.PayloadType, len(payload), payload))
						}
						sig, err := signer.Sign(message)
						require.NoError(t, err)
						e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
					})
					_, err := solutionhost.VerifyDelivered(context.Background(), changed, verifier)
					if usePAE {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, solutionhost.ErrUnsigned)
						require.ErrorContains(t, err, "invalid DSSE signature")
					}
				}
				want := solutionhost.SignerIdentity{KeyID: signer.KeyID(), Kind: kind}
				require.Equal(t, want, delivered.Signer())
				require.Equal(t, payload, delivered.Payload())
			})
		}
	}
}

func TestPinnedKeyVerificationRefusesUntrustedCarriers(t *testing.T) {
	signer, other := signerFor(t, testKeyID), signerFor(t, "other-key")
	verifier := verifierFor(t,
		pinFor(t, signer, solutionhost.KeyKindRelease, testDomain),
		pinFor(t, other, solutionhost.KeyKindPerson, testDomain))
	carrier := signedValid(t)
	t.Run("unpinned key", func(t *testing.T) {
		_, err := solutionhost.VerifyDelivered(context.Background(), signedWith(t, carrier.Document, signerFor(t, "unknown")), verifier)
		require.ErrorIs(t, err, solutionhost.ErrUnsigned)
		require.ErrorContains(t, err, "untrusted key ID")
	})
	t.Run("tampered document", func(t *testing.T) {
		tampered := *carrier
		document := valid(t)
		document.Generation++
		var err error
		tampered.Document, err = document.CanonicalBytes()
		require.NoError(t, err)
		_, err = solutionhost.VerifyDelivered(context.Background(), &tampered, verifier)
		require.ErrorIs(t, err, solutionhost.ErrUnsigned)
		require.ErrorContains(t, err, "payload does not match carried document")
	})
	t.Run("another pinned key's ID", func(t *testing.T) {
		// Both keys are trusted: keyid must select the actual signing key,
		// not merely some key in the set that can verify this signature.
		changed := changeEnvelope(t, carrier, func(b *wireEnvelope) {
			b.Signatures[0].KeyID = other.KeyID()
		})
		_, err := solutionhost.VerifyDelivered(context.Background(), changed, verifier)
		require.ErrorIs(t, err, solutionhost.ErrUnsigned)
		require.ErrorContains(t, err, "invalid DSSE signature")
	})
	t.Run("same ID different public key", func(t *testing.T) {
		wrongKey := differentKey(t, signer.KeyID())
		_, err := solutionhost.VerifyDelivered(context.Background(), signedWith(t, carrier.Document, wrongKey), verifier)
		require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	})
	t.Run("key not allowed for ownership domain", func(t *testing.T) {
		wrongDomain := verifierFor(t, pinFor(t, signer, solutionhost.KeyKindRelease, "other-domain"))
		_, err := solutionhost.VerifyDelivered(context.Background(), carrier, wrongDomain)
		require.ErrorIs(t, err, solutionhost.ErrWrongDomain)
		// Restoring the allowed domain makes the identical carrier valid.
		_, err = solutionhost.VerifyDelivered(context.Background(), carrier, verifier)
		require.NoError(t, err)
	})
	t.Run("tampered payload and document", func(t *testing.T) {
		document := valid(t)
		document.Generation++
		payload, err := document.CanonicalBytes()
		require.NoError(t, err)
		changed := changeEnvelope(t, carrier, func(e *wireEnvelope) {
			e.Payload = base64.StdEncoding.EncodeToString(payload)
		})
		changed.Document = payload
		_, err = solutionhost.VerifyDelivered(context.Background(), changed, verifier)
		require.ErrorIs(t, err, solutionhost.ErrUnsigned)
		require.ErrorContains(t, err, "invalid DSSE signature")
	})
	t.Run("signed with wrong payloadType", func(t *testing.T) {
		// A valid signature over a different type must still be refused.
		changed := changeEnvelope(t, carrier, func(e *wireEnvelope) {
			e.PayloadType = "application/vnd.codefly.solution-presence+json"
			message := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(e.PayloadType), e.PayloadType, len(carrier.Document), carrier.Document))
			signature, err := signer.Sign(message)
			require.NoError(t, err)
			e.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
		})
		_, err := solutionhost.VerifyDelivered(context.Background(), changed, verifier)
		require.ErrorIs(t, err, solutionhost.ErrUnsigned)
		require.ErrorContains(t, err, "payloadType")
	})
	for name, change := range map[string]func(*wireEnvelope){
		"missing keyid":            func(e *wireEnvelope) { e.Signatures[0].KeyID = "" },
		"missing signature":        func(e *wireEnvelope) { e.Signatures[0].Sig = "" },
		"invalid signature base64": func(e *wireEnvelope) { e.Signatures[0].Sig = "!" },
		"invalid payload base64":   func(e *wireEnvelope) { e.Payload = "!" },
		"missing payload":          func(e *wireEnvelope) { e.Payload = "" },
		"payload mismatch":         func(e *wireEnvelope) { e.Payload = base64.StdEncoding.EncodeToString([]byte("tampered")) },
		"retired payloadType":      func(e *wireEnvelope) { e.PayloadType = "application/vnd.codefly.solution-authority+json" },
		"unknown payloadType":      func(e *wireEnvelope) { e.PayloadType = "application/json" },
		"missing payloadType":      func(e *wireEnvelope) { e.PayloadType = "" },
		"no signatures":            func(e *wireEnvelope) { e.Signatures = nil },
		"two signatures":           func(e *wireEnvelope) { e.Signatures = append(e.Signatures, e.Signatures[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := solutionhost.VerifyDelivered(context.Background(), changeEnvelope(t, carrier, change), verifier)
			require.ErrorIs(t, err, solutionhost.ErrUnsigned)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := verifier.VerifyEnvelope(ctx, carrier.Document, carrier.Envelope)
	require.ErrorIs(t, err, context.Canceled)
}

func TestPinnedKeySetIsStrictAndImmutable(t *testing.T) {
	base := pinFor(t, signerFor(t, testKeyID), solutionhost.KeyKindRelease, testDomain)
	for name, change := range map[string]func(*solutionhost.PinnedKey){
		"empty ID":         func(p *solutionhost.PinnedKey) { p.KeyID = "" },
		"non-UTF8 ID":      func(p *solutionhost.PinnedKey) { p.KeyID = "key\xff" },
		"blank ID":         func(p *solutionhost.PinnedKey) { p.KeyID = " " },
		"padded ID":        func(p *solutionhost.PinnedKey) { p.KeyID += " " },
		"multiline ID":     func(p *solutionhost.PinnedKey) { p.KeyID += "\nkey" },
		"unknown kind":     func(p *solutionhost.PinnedKey) { p.Kind = "workload" },
		"empty kind":       func(p *solutionhost.PinnedKey) { p.Kind = "" },
		"no domains":       func(p *solutionhost.PinnedKey) { p.OwnershipDomains = nil },
		"empty domain":     func(p *solutionhost.PinnedKey) { p.OwnershipDomains = []string{""} },
		"blank domain":     func(p *solutionhost.PinnedKey) { p.OwnershipDomains = []string{" "} },
		"multiline domain": func(p *solutionhost.PinnedKey) { p.OwnershipDomains = []string{"alpha\nbeta"} },
		"duplicate domain": func(p *solutionhost.PinnedKey) { p.OwnershipDomains = []string{"alpha", "alpha"} },
		"no key":           func(p *solutionhost.PinnedKey) { p.PublicKeyPEM = "" },
		"invalid DER": func(p *solutionhost.PinnedKey) {
			p.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}))
		},
		"wrong PEM type": func(p *solutionhost.PinnedKey) {
			p.PublicKeyPEM = strings.ReplaceAll(p.PublicKeyPEM, "PUBLIC KEY", "CERTIFICATE")
		},
		"PEM headers": func(p *solutionhost.PinnedKey) {
			p.PublicKeyPEM = strings.Replace(p.PublicKeyPEM, "KEY-----\n", "KEY-----\nComment: unexpected\n", 1)
		},
		"two keys":        func(p *solutionhost.PinnedKey) { p.PublicKeyPEM += p.PublicKeyPEM },
		"leading garbage": func(p *solutionhost.PinnedKey) { p.PublicKeyPEM = "garbage\n" + p.PublicKeyPEM },
		"malformed preceding block": func(p *solutionhost.PinnedKey) {
			p.PublicKeyPEM = "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----\n" + p.PublicKeyPEM
		},
		"trailing garbage": func(p *solutionhost.PinnedKey) { p.PublicKeyPEM += "garbage" },
	} {
		t.Run(name, func(t *testing.T) {
			pin := base
			change(&pin)
			_, err := solutionhost.NewPinnedKeySet(pin)
			require.Error(t, err)
		})
	}
	_, err := solutionhost.NewPinnedKeySet()
	require.Error(t, err)
	_, err = solutionhost.NewPinnedKeySet(base, base)
	require.ErrorContains(t, err, "duplicate key ID")
	for _, keys := range []*solutionhost.PinnedKeySet{nil, {}} {
		_, err := solutionhost.NewVerifier(keys)
		require.Error(t, err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, public := range []any{p384.Public(), rsaKey.Public()} {
		der, err := x509.MarshalPKIXPublicKey(public)
		require.NoError(t, err)
		pin := base
		pin.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		_, err = solutionhost.NewPinnedKeySet(pin)
		require.ErrorContains(t, err, "Ed25519 or ECDSA P-256")
	}
	keys, err := solutionhost.NewPinnedKeySet(base)
	require.NoError(t, err)
	verifier, err := solutionhost.NewVerifier(keys)
	require.NoError(t, err)
	base.OwnershipDomains[0] = "other-domain"
	base.Kind = solutionhost.KeyKindPerson
	policy := keys.DomainsBySigner()
	policy[base.KeyID][0] = "other-domain"
	delete(policy, base.KeyID)
	delivered, err := solutionhost.VerifyDelivered(context.Background(), signedValid(t), verifier)
	require.NoError(t, err)
	require.Equal(t, solutionhost.KeyKindRelease, delivered.Signer().Kind)
	require.Equal(t, []string{testDomain}, keys.DomainsBySigner()[base.KeyID])
	identity := delivered.Signer()
	identity.KeyID = "other-key"
	require.Equal(t, testKeyID, delivered.Signer().KeyID)
	replacement, err := solutionhost.NewPinnedKeySet(pinFor(t, differentKey(t, base.KeyID), solutionhost.KeyKindPerson, "other-domain"))
	require.NoError(t, err)
	*keys = *replacement
	delivered, err = solutionhost.VerifyDelivered(context.Background(), signedValid(t), verifier)
	require.NoError(t, err, "replacing the caller's pin set must not change an existing verifier")
	require.Equal(t, solutionhost.KeyKindRelease, delivered.Signer().Kind)
}

func TestEnvelopeRejectsUnexpectedWireShapes(t *testing.T) {
	carrier := signedValid(t)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal(carrier.Envelope, &envelope))
	for _, field := range []string{"publicKey", "certificate", "verificationMaterial", "algorithm", "url"} {
		t.Run(field, func(t *testing.T) {
			envelope[field] = "unexpected"
			encoded, err := json.Marshal(envelope)
			require.NoError(t, err)
			_, err = testVerifier(t).VerifyEnvelope(context.Background(), carrier.Document, encoded)
			require.ErrorContains(t, err, "unknown field")
			delete(envelope, field)
		})
	}
	for name, encoded := range map[string][]byte{
		"trailing object":       append(bytes.Clone(carrier.Envelope), []byte(` {}`)...),
		"trailing delimiter":    append(bytes.Clone(carrier.Envelope), '}'),
		"null":                  []byte(`null`),
		"array":                 []byte(`[]`),
		"payload byte array":    []byte(`{"payloadType":"application/json","payload":[1,2],"signatures":[]}`),
		"signature byte array":  []byte(`{"payloadType":"application/json","payload":"e30=","signatures":[{"keyid":"key","sig":[1,2]}]}`),
		"signature extra field": []byte(`{"payloadType":"application/json","payload":"e30=","signatures":[{"keyid":"key","sig":"e30=","algorithm":"unknown"}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := testVerifier(t).VerifyEnvelope(context.Background(), carrier.Document, encoded)
			require.Error(t, err)
		})
	}
}

func TestDSSEAcceptsURLSafeBase64(t *testing.T) {
	carrier := signedValid(t)
	changed := changeEnvelope(t, carrier, func(e *wireEnvelope) {
		payload, err := base64.StdEncoding.DecodeString(e.Payload)
		require.NoError(t, err)
		sig, err := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
		require.NoError(t, err)
		e.Payload = base64.URLEncoding.EncodeToString(payload)
		e.Signatures[0].Sig = base64.URLEncoding.EncodeToString(sig)
	})
	_, err := solutionhost.VerifyDelivered(context.Background(), changed, testVerifier(t))
	require.NoError(t, err)
}

// A small-order Ed25519 point accepts a fixed signature for every message, and
// a non-canonical encoding names a point twice: neither may become a pin.
func TestPinnedKeySetRefusesWeakEd25519Keys(t *testing.T) {
	pinFor := func(t *testing.T, raw []byte) solutionhost.PinnedKey {
		t.Helper()
		der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
		require.NoError(t, err)
		return solutionhost.PinnedKey{
			KeyID: "release", Kind: solutionhost.KeyKindRelease, OwnershipDomains: []string{"example"},
			PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		}
	}
	for _, encoded := range []string{
		// The eight points of small order.
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		// The identity and the point of order 2 with x's sign bit set: x = 0,
		// so each is a second encoding of the same small-order point.
		"0100000000000000000000000000000000000000000000000000000000000080",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		// Non-canonical encodings: y = p, y = p + 1, and y = p with x's sign bit.
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		t.Run(encoded[:8]+"…"+encoded[62:], func(t *testing.T) {
			raw, err := hex.DecodeString(encoded)
			require.NoError(t, err)
			_, err = solutionhost.NewPinnedKeySet(pinFor(t, raw))
			require.Error(t, err)
		})
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = solutionhost.NewPinnedKeySet(pinFor(t, public))
	require.NoError(t, err, "an ordinary key still pins")
}
