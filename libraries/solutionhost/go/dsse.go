package solutionhost

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// PayloadTypeModuleManifest identifies a canonical module manifest in DSSE.
// It and PayloadTypeModuleEnvelope are the two payload types this package
// signs or verifies.
const PayloadTypeModuleManifest = "application/vnd.codefly.module-manifest+json"

// Strings enforce base64 on the wire: encoding/json also accepts byte arrays
// for []byte, which is not the DSSE envelope format.
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// payloadTypeFor names the DSSE payload type of a document from the schema
// inside its bytes. Signing and verifying both derive it here, never from the
// envelope, so the type a signature binds is the type the document declares.
func payloadTypeFor(document []byte) (string, error) {
	switch schema := documentSchema(document); schema {
	case SchemaModuleManifestV1:
		return PayloadTypeModuleManifest, nil
	case SchemaModuleEnvelopeV1:
		return PayloadTypeModuleEnvelope, nil
	default:
		if replacedFamily(schema) {
			return "", schemaRefusal(schema, SchemaModuleManifestV1)
		}
		return "", fmt.Errorf("%w: %q (this Core signs %q and %q)", ErrSchema, schema, SchemaModuleManifestV1, SchemaModuleEnvelopeV1)
	}
}

// pae implements DSSE pre-authentication encoding. Lengths count bytes, and
// the payload is appended verbatim, including any whitespace or binary bytes.
func pae(payloadType string, payload []byte) []byte {
	header := "DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " "
	return append([]byte(header), payload...)
}

func decodeEnvelope(encoded []byte) (dsseEnvelope, []byte, []byte, error) {
	var envelope dsseEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return envelope, nil, nil, fmt.Errorf("decode DSSE envelope: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return envelope, nil, nil, fmt.Errorf("trailing input after DSSE envelope")
	}
	if len(envelope.Signatures) != 1 {
		return envelope, nil, nil, fmt.Errorf("DSSE envelope requires exactly one signature")
	}
	if !keyName(envelope.Signatures[0].KeyID) {
		return envelope, nil, nil, fmt.Errorf("DSSE signature requires a valid keyid")
	}
	payload, err := decodeBase64(envelope.Payload)
	if err != nil || len(payload) == 0 {
		return envelope, nil, nil, fmt.Errorf("DSSE payload must be nonempty base64")
	}
	sig, err := decodeBase64(envelope.Signatures[0].Sig)
	if err != nil || len(sig) == 0 {
		return envelope, nil, nil, fmt.Errorf("DSSE signature must be nonempty base64")
	}
	return envelope, payload, sig, nil
}

// DSSE permits both the standard and URL-safe base64 alphabets.
func decodeBase64(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err == nil {
		return decoded, nil
	}
	return base64.URLEncoding.Strict().DecodeString(encoded)
}

func verifySignature(public crypto.PublicKey, message, signature []byte) error {
	if err := validatePublicKey(public); err != nil {
		return err
	}
	valid := false
	switch key := public.(type) {
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, message, signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		valid = ecdsa.VerifyASN1(key, digest[:], signature)
	}
	if !valid {
		return fmt.Errorf("invalid DSSE signature")
	}
	return nil
}
