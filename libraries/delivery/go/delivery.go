// Package delivery signs and verifies the authority's own delivery document:
// what a module declares that the authority enforces and core's module manifest
// does not carry, each method's policy first. It is signed in the same DSSE
// envelope format, by the same release key, as the core manifest it is
// delivered with, and names that manifest's digest, so the two cannot be mixed
// across deliveries.
package delivery

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// PayloadType names the authority's document inside its envelope.
const PayloadType = "application/vnd.codefly.authority-manifest+proto"

type envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Sign wraps document in an envelope signed by sign under keyID.
func Sign(document []byte, keyID string, sign func(message []byte) ([]byte, error)) ([]byte, error) {
	if keyID == "" || len(document) == 0 {
		return nil, errors.New("delivery: signing needs a key id and a document")
	}
	sig, err := sign(pae(document))
	if err != nil {
		return nil, fmt.Errorf("delivery: sign with %q: %w", keyID, err)
	}
	return json.Marshal(envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(document),
		Signatures:  []signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	})
}

// Verify checks that encoded is one signature over document by the key keyID
// names in keys, and returns that key id.
func Verify(document, encoded []byte, keys map[string]crypto.PublicKey) (string, error) {
	var e envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&e); err != nil {
		return "", fmt.Errorf("delivery: the envelope does not decode: %w", err)
	}
	if e.PayloadType != PayloadType {
		return "", fmt.Errorf("delivery: the envelope carries %q, not the authority's document", e.PayloadType)
	}
	if len(e.Signatures) != 1 {
		return "", errors.New("delivery: the envelope must carry exactly one signature")
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil || !bytes.Equal(payload, document) {
		return "", errors.New("delivery: the envelope's payload is not the document delivered with it")
	}
	keyID := e.Signatures[0].KeyID
	public, ok := keys[keyID]
	if !ok {
		return "", fmt.Errorf("delivery: key %q is not pinned", keyID)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signatures[0].Sig)
	if err != nil {
		return "", errors.New("delivery: the signature is not base64")
	}
	message := pae(document)
	valid := false
	switch key := public.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, message, sig)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		valid = ecdsa.VerifyASN1(key, digest[:], sig)
	}
	if !valid {
		return "", fmt.Errorf("delivery: the signature by %q does not verify", keyID)
	}
	return keyID, nil
}

// Digest names a document as the authority's document names the core
// manifest it travels with: "sha256:<hex>".
func Digest(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func pae(payload []byte) []byte {
	return append([]byte("DSSEv1 "+strconv.Itoa(len(PayloadType))+" "+PayloadType+" "+strconv.Itoa(len(payload))+" "), payload...)
}
