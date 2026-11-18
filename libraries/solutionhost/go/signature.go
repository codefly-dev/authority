package solutionhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// SignedFileName is the conventional name of a delivered signed document.
//
// The carrier is JSON, not YAML, even under this extension. The verified
// payload is the document's canonical bytes verbatim, and a YAML emitter folds
// a long scalar across lines — which would change those bytes and turn every
// delivered signature into a verification failure nobody can read. JSON has no
// folding, and a JSON object is valid YAML, so the carrier still travels
// through a pipeline that classifies delivery documents by this extension.
const SignedFileName = "module-manifest.signed.codefly.yaml"

var (
	// ErrUnsigned means a carrier is not a signed document this package reads
	// (a manifest or an envelope) — a missing document, a missing envelope, an
	// invalid carrier shape, or an attestation that does not hold. Every such
	// refusal matches it; one that knows which document it refused names that
	// document, so an envelope refusal never reads as a manifest's.
	ErrUnsigned = errors.New("the carrier is not a signed module document")

	// ErrNotCanonical means a payload is not the canonical encoding of the
	// document it decodes to. It is refused even when the signature over those
	// bytes is genuine: a signer and a host that disagree about which bytes
	// represent the document disagree about what was approved, and the host's
	// stored digest would not match the payload that was attested. Like
	// ErrUnsigned, each refusal names the document it refused.
	ErrNotCanonical = errors.New("the payload is not its module document's canonical encoding")

	errUnsignedManifest     = documentRefusal{ErrUnsigned, "module manifest is not a signed document"}
	errUnsignedEnvelope     = documentRefusal{ErrUnsigned, "module envelope is not a signed document"}
	errManifestNotCanonical = documentRefusal{ErrNotCanonical, "module manifest payload is not its canonical encoding"}
	errEnvelopeNotCanonical = documentRefusal{ErrNotCanonical, "module envelope payload is not its canonical encoding"}
)

// documentRefusal is a refusal of one named document: it reads as that
// document's and matches the sentinel it specializes under errors.Is.
type documentRefusal struct {
	sentinel error
	text     string
}

func (r documentRefusal) Error() string { return r.text }

func (r documentRefusal) Unwrap() error { return r.sentinel }

// Signed carries a canonical document — a manifest or an envelope — and the
// DSSE envelope attesting it.
// Verification is offline, using only the Go standard library and the host's
// pinned public keys. No third-party service or carrier-supplied trust material
// participates. SignEnvelope uses a caller-held Signer to produce the envelope.
//
// ParseSigned only decodes the carrier. VerifyDelivered verifies it before
// returning a manifest for admission, VerifyDeliveredEnvelope an envelope.
type Signed struct {
	// Document contains the canonical document bytes verbatim. They must be
	// identical to the envelope's decoded payload. Re-encoding is not
	// verification.
	Document json.RawMessage `json:"document"`

	// Envelope is a DSSE JSON object with exactly one signature.
	Envelope json.RawMessage `json:"envelope"`
}

// ParseSigned decodes a signature carrier. Decoding is strict: an unknown field
// is an error, which is what refuses a carrier that ships a key, a certificate
// or a URL alongside its envelope instead of quietly dropping it. Verifier
// decodes and checks the envelope; this parser checks the carrier shape.
func ParseSigned(data []byte) (*Signed, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var signed Signed
	if err := decoder.Decode(&signed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsigned, err)
	}
	// Decoder.More() is an array/object iteration check, not an end-of-input
	// check: a carrier followed by a stray "]" or "}" passes it even though
	// the whole input is not valid JSON. Requiring a second decode to return
	// io.EOF is what actually establishes that nothing follows.
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: the carrier holds more than one document", ErrUnsigned)
		}
		return nil, fmt.Errorf("%w: trailing input after the carrier: %v", ErrUnsigned, err)
	}
	if err := signed.validate(); err != nil {
		return nil, err
	}
	return &signed, nil
}

func (signed *Signed) validate() error {
	if len(bytes.TrimSpace(signed.Document)) == 0 {
		return fmt.Errorf("%w: the carrier holds no document", ErrUnsigned)
	}
	// An envelope that is absent, empty or JSON null is no attestation. The shape
	// parser requires its presence; Verifier checks its contents.
	trimmed := bytes.TrimSpace(signed.Envelope)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("%w: the carrier holds no signature envelope", ErrUnsigned)
	}
	// An object, because an envelope is one. Refusing the other JSON shapes keeps
	// a single wire form: a base64 string of an envelope would also decode as
	// valid JSON here, and two accepted shapes is two code paths downstream.
	if trimmed[0] != '{' {
		return fmt.Errorf("%w: the signature envelope must be a JSON object", ErrUnsigned)
	}
	return nil
}

// ManifestFromVerified turns payload bytes the caller HAS ALREADY VERIFIED
// into a manifest. It verifies no signature: a caller that reaches it without
// verifying the envelope over these exact bytes has authenticated nothing.
// VerifyDelivered is the entrypoint that does both.
//
// What it owns is the document half: the strict parse, the schema (inside the
// signed bytes), and the canonical round-trip, which refuses a payload that is
// not the canonical encoding of the manifest it decodes to — even under a
// genuine signature, because a signer and a host that disagree about which
// bytes are the manifest disagree about what was delivered.
func ManifestFromVerified(payload []byte) (*ModuleManifest, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, fmt.Errorf("%w: no payload", errUnsignedManifest)
	}
	manifest, err := Parse(payload)
	if err != nil {
		return nil, err
	}
	encoded, err := manifest.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, payload) {
		return nil, errManifestNotCanonical
	}
	return manifest, nil
}

// documentSchema reads the document kind. Invalid JSON or a missing schema
// returns an empty string, which no supported document kind accepts.
func documentSchema(payload []byte) string {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return ""
	}
	return header.Schema
}

// SignedPayload returns the canonical bytes of a valid manifest: what
// SignEnvelope signs, so the signing pipeline never reimplements the encoding.
func SignedPayload(manifest *ModuleManifest) ([]byte, error) {
	return manifest.CanonicalBytes()
}

// Carrier assembles the delivered form from a payload and the envelope attesting
// it. SignEnvelope produces an envelope using a caller-held key. The payload is a
// canonical module manifest or a canonical module envelope, told apart by the
// schema inside it; the carrier is one shape for both, and VerifyDelivered or
// VerifyDeliveredEnvelope is what says which document a host accepts from it.
// Carrier checks the document shape; acceptance still requires the host's
// pinned-key Verifier.
func Carrier(payload []byte, envelope json.RawMessage) (*Signed, error) {
	signed := &Signed{
		Document: bytes.Clone(payload),
		Envelope: bytes.Clone(envelope),
	}
	if err := signed.validate(); err != nil {
		return nil, err
	}
	// The payload must be a canonical document, or the carrier is built around
	// bytes no host can round-trip. Checking it here fails the render that
	// produced it rather than the host that received it.
	switch SchemaOf(payload) {
	case SchemaModuleManifestV1:
		if _, err := ManifestFromVerified(payload); err != nil {
			return nil, fmt.Errorf("%w: the payload is not a canonical module manifest: %w", errUnsignedManifest, err)
		}
	case SchemaModuleEnvelopeV1:
		if _, err := EnvelopeFromVerified(payload); err != nil {
			return nil, fmt.Errorf("%w: the payload is not a canonical module envelope: %w", errUnsignedEnvelope, err)
		}
	default:
		_, err := payloadTypeFor(payload)
		return nil, fmt.Errorf("%w: the payload is neither a module manifest nor a module envelope: %w", ErrUnsigned, err)
	}
	return signed, nil
}

// MarshalSigned renders a carrier for delivery. The output is JSON, for the
// reason SignedFileName gives.
func MarshalSigned(signed *Signed) ([]byte, error) {
	if signed == nil {
		return nil, fmt.Errorf("%w: no signed document", ErrUnsigned)
	}
	if err := signed.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(signed)
}
