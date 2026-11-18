package solutionhost

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// KeyKind is the platform's classification of a pinned signing key.
type KeyKind string

const (
	KeyKindRelease KeyKind = "release"
	KeyKindPerson  KeyKind = "person"
)

// PinnedKey is supplied by the host's trust anchor, never by a carrier.
// PublicKeyPEM must contain exactly one PKIX PUBLIC KEY (Ed25519 or ECDSA P-256).
type PinnedKey struct {
	KeyID            string
	PublicKeyPEM     string
	Kind             KeyKind
	OwnershipDomains []string
}

// PinnedKeySet is an immutable, validated mapping from key ID to key and policy.
// Construct it with NewPinnedKeySet; its zero value trusts no keys.
type PinnedKeySet struct {
	keys map[string]pinnedKey
}

type pinnedKey struct {
	identity SignerIdentity
	domains  []string
	public   crypto.PublicKey
}

// SignerIdentity attests the ID and kind of the pinned key that verified a
// signature. Kind is read from the host's pins, never from delivery metadata.
type SignerIdentity struct {
	KeyID string
	Kind  KeyKind
}

// NewPinnedKeySet validates every pin and rejects duplicate IDs, unsupported
// keys or kinds, and absent, blank or repeated ownership domains. Taking a list
// preserves duplicate IDs until they can be refused instead of overwritten.
func NewPinnedKeySet(pins ...PinnedKey) (*PinnedKeySet, error) {
	if len(pins) == 0 {
		return nil, fmt.Errorf("pinned keys: at least one key is required")
	}
	set := &PinnedKeySet{keys: make(map[string]pinnedKey, len(pins))}
	for _, pin := range pins {
		if !keyName(pin.KeyID) {
			return nil, fmt.Errorf("pinned keys: invalid key ID %q", pin.KeyID)
		}
		if _, exists := set.keys[pin.KeyID]; exists {
			return nil, fmt.Errorf("pinned keys: duplicate key ID %q", pin.KeyID)
		}
		if pin.Kind != KeyKindRelease && pin.Kind != KeyKindPerson {
			return nil, fmt.Errorf("pinned key %q: unknown kind %q", pin.KeyID, pin.Kind)
		}
		if len(pin.OwnershipDomains) == 0 {
			return nil, fmt.Errorf("pinned key %q: no ownership domains", pin.KeyID)
		}
		for i, domain := range pin.OwnershipDomains {
			if !keyName(domain) || slices.Contains(pin.OwnershipDomains[:i], domain) {
				return nil, fmt.Errorf("pinned key %q: invalid or repeated ownership domain %q", pin.KeyID, domain)
			}
		}
		encoded := bytes.TrimSpace([]byte(pin.PublicKeyPEM))
		block, rest := pem.Decode(encoded)
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 ||
			len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(encoded, []byte("-----BEGIN PUBLIC KEY-----")) ||
			bytes.Count(encoded, []byte("-----BEGIN ")) != 1 {
			return nil, fmt.Errorf("pinned key %q: expected exactly one PUBLIC KEY PEM block", pin.KeyID)
		}
		public, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pinned key %q: %w", pin.KeyID, err)
		}
		if err := validatePublicKey(public); err != nil {
			return nil, fmt.Errorf("pinned key %q: %w", pin.KeyID, err)
		}
		set.keys[pin.KeyID] = pinnedKey{
			identity: SignerIdentity{KeyID: pin.KeyID, Kind: pin.Kind},
			domains:  slices.Clone(pin.OwnershipDomains),
			public:   public,
		}
	}
	return set, nil
}

func keyName(value string) bool {
	return value != "" && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func validatePublicKey(public crypto.PublicKey) error {
	switch key := public.(type) {
	case ed25519.PublicKey:
		if len(key) == ed25519.PublicKeySize && canonicalEd25519(key) && !smallOrderEd25519(key) {
			return nil
		}
	case *ecdsa.PublicKey:
		if key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y) {
			return nil
		}
	}
	return fmt.Errorf("public key must be Ed25519 or ECDSA P-256")
}

// ed25519P is the field prime 2^255 - 19.
var ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// canonicalEd25519 reports whether the encoded y coordinate is below the field
// prime: a non-canonical encoding names a point a second time and is refused,
// as libsodium refuses it.
func canonicalEd25519(key ed25519.PublicKey) bool {
	le := make([]byte, len(key))
	copy(le, key)
	le[31] &= 0x7f // the sign bit of x is not part of y
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be).Cmp(ed25519P) < 0
}

// ed25519SmallOrder lists the encodings of the points of small order (the
// identity, the point of order 2, and those of orders 4 and 8) with the sign
// bit of x cleared. A pin on one of them would accept a fixed signature for
// every message. The sign bit is cleared before comparing, as libsodium does:
// the decoder accepts x = 0 with the sign bit set, so the identity and the
// point of order 2 each have a second encoding that names the same point.
var ed25519SmallOrder = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
}

func smallOrderEd25519(key ed25519.PublicKey) bool {
	masked := make([]byte, len(key))
	copy(masked, key)
	masked[31] &= 0x7f
	return slices.Contains(ed25519SmallOrder, hex.EncodeToString(masked))
}

// DomainsBySigner returns a fresh copy of the pinned domain policy: which
// ownership domains each key may deliver under. Mutating it cannot change the
// pins or an existing verifier.
func (set *PinnedKeySet) DomainsBySigner() map[string][]string {
	policy := make(map[string][]string)
	if set != nil {
		for id, key := range set.keys {
			policy[id] = slices.Clone(key.domains)
		}
	}
	return policy
}

// Verifier checks DSSE envelopes offline using only the Go standard library
// and pinned public keys. No third-party service, certificate, log or timestamp
// participates in verification.
type Verifier struct {
	keys *PinnedKeySet
}

// NewVerifier holds an immutable snapshot of the host's pins. Rotation is a
// new pin set supplied by the host's trust anchor.
func NewVerifier(keys *PinnedKeySet) (*Verifier, error) {
	if keys == nil || len(keys.keys) == 0 {
		return nil, fmt.Errorf("verifier: no pinned keys")
	}
	snapshot := *keys
	return &Verifier{keys: &snapshot}, nil
}

// VerifyEnvelope checks one DSSE signature against the pin selected by keyid.
// The payloadType must match the document's schema, and the decoded payload
// must be byte-identical to document. Identity is returned only after the
// signature over DSSE's PAE verifies. The envelope supplies no trust material.
// Use VerifyDelivered or VerifyDeliveredEnvelope to also check the canonical
// document and its ownership domain.
func (v *Verifier) VerifyEnvelope(ctx context.Context, document []byte, encoded json.RawMessage) (SignerIdentity, error) {
	if err := ctx.Err(); err != nil {
		return SignerIdentity{}, err
	}
	if v == nil || v.keys == nil || len(v.keys.keys) == 0 {
		return SignerIdentity{}, fmt.Errorf("no pinned-key verifier")
	}
	envelope, payload, signature, err := decodeEnvelope(encoded)
	if err != nil {
		return SignerIdentity{}, err
	}
	if !bytes.Equal(payload, document) {
		return SignerIdentity{}, fmt.Errorf("envelope payload does not match carried document")
	}
	payloadType, err := payloadTypeFor(document)
	if err != nil {
		return SignerIdentity{}, err
	}
	if envelope.PayloadType != payloadType {
		return SignerIdentity{}, fmt.Errorf("envelope payloadType %q does not match document type %q", envelope.PayloadType, payloadType)
	}
	id := envelope.Signatures[0].KeyID
	key, ok := v.keys.keys[id]
	if !ok {
		return SignerIdentity{}, fmt.Errorf("untrusted key ID %q", id)
	}
	if err := verifySignature(key.public, pae(payloadType, payload), signature); err != nil {
		return SignerIdentity{}, err
	}
	return key.identity, nil
}

func (v *Verifier) checkDomain(signer SignerIdentity, domain string) error {
	if !slices.Contains(v.keys.keys[signer.KeyID].domains, domain) {
		return fmt.Errorf("%w: pinned key %q may not deliver under ownership domain %q", ErrWrongDomain, signer.KeyID, domain)
	}
	return nil
}
