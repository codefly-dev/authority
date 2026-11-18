package solutionhost

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Signer is a platform-owned key, held locally or by a custody service such as
// Vault Transit. Sign receives the full message: Ed25519 signs it directly;
// ECDSA P-256 signs its SHA-256 digest and returns an ASN.1 DER signature.
// Adapters own authentication and transport to their keychain or custody service.
type Signer interface {
	KeyID() string
	Public() crypto.PublicKey
	Sign(message []byte) ([]byte, error)
}

// SignEnvelope produces a DSSE envelope with exactly one signature over PAE.
// The payloadType is PayloadTypeModuleManifest or PayloadTypeModuleEnvelope,
// from the schema inside the payload. Only the key ID travels with the
// signature; the host must already pin the public key. Payload should come
// from SignedPayload or ModuleEnvelope.CanonicalBytes; Carrier enforces
// canonical form.
func SignEnvelope(payload []byte, signer Signer) (json.RawMessage, error) {
	if signer == nil || !keyName(signer.KeyID()) {
		return nil, fmt.Errorf("sign envelope: a signer with a valid key ID is required")
	}
	id, public := signer.KeyID(), signer.Public()
	if err := validatePublicKey(public); err != nil {
		return nil, err
	}
	payload = bytes.Clone(payload)
	payloadType, err := payloadTypeFor(payload)
	if err != nil {
		return nil, err
	}
	message := pae(payloadType, payload)
	sig, err := signer.Sign(bytes.Clone(message))
	if err != nil {
		return nil, fmt.Errorf("sign envelope with %q: %w", id, err)
	}
	// Fail at the producer if an adapter signs the wrong bytes or uses a
	// different key than Public advertises.
	if err := verifySignature(public, message, sig); err != nil {
		return nil, fmt.Errorf("sign envelope with %q: signer returned an invalid signature: %w", id, err)
	}
	return json.Marshal(dsseEnvelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []dsseSignature{{KeyID: id, Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
}

// InMemorySigner holds a private key for tests, fixtures or local signing.
// Production custody adapters implement Signer without exporting private keys.
type InMemorySigner struct {
	id  string
	key crypto.Signer
}

// NewInMemorySigner copies an Ed25519 or ECDSA P-256 private key. The caller
// generates or loads the key; this helper does not resolve credentials.
func NewInMemorySigner(keyID string, privateKey crypto.PrivateKey) (*InMemorySigner, error) {
	if !keyName(keyID) {
		return nil, fmt.Errorf("signer: invalid key ID %q", keyID)
	}
	var key crypto.Signer
	switch value := privateKey.(type) {
	case ed25519.PrivateKey:
		if len(value) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("signer: invalid Ed25519 private key")
		}
		key = value
	case *ecdsa.PrivateKey:
		if value == nil || value.D == nil {
			return nil, fmt.Errorf("signer: invalid ECDSA private key")
		}
		key = value
	default:
		return nil, fmt.Errorf("signer: private key must be Ed25519 or ECDSA P-256")
	}
	if err := validatePublicKey(key.Public()); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	copy, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	return &InMemorySigner{id: keyID, key: copy.(crypto.Signer)}, nil
}

func (s *InMemorySigner) KeyID() string { return s.id }

// Public returns a copy of the public key.
func (s *InMemorySigner) Public() crypto.PublicKey {
	der, _ := x509.MarshalPKIXPublicKey(s.key.Public())
	public, _ := x509.ParsePKIXPublicKey(der)
	return public
}

// Sign implements Signer with Ed25519 or ECDSA P-256/SHA-256.
func (s *InMemorySigner) Sign(message []byte) ([]byte, error) {
	if _, ok := s.key.Public().(ed25519.PublicKey); ok {
		return s.key.Sign(rand.Reader, message, crypto.Hash(0))
	}
	digest := sha256.Sum256(message)
	return s.key.Sign(rand.Reader, digest[:], crypto.SHA256)
}
