package solutionhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// SchemaModuleEnvelopeV1 is the only envelope schema this package reads.
	// Like the manifest's, it is inside the signed canonical bytes, so a
	// signature is bound to the document type as well as its contents.
	SchemaModuleEnvelopeV1 = "codefly/module-envelope/v1"

	// PayloadTypeModuleEnvelope identifies a canonical module envelope in DSSE.
	// It differs from PayloadTypeModuleManifest, and DSSE signs the payload type
	// with the payload, so a manifest's signature never verifies as an
	// envelope's and an envelope's never as a manifest's.
	PayloadTypeModuleEnvelope = "application/vnd.codefly.module-envelope+json"

	// EnvelopeSignedFileName is the conventional name of a delivered signed
	// envelope. The carrier is JSON under this extension, for the reason
	// SignedFileName gives.
	EnvelopeSignedFileName = "module-envelope.signed.codefly.yaml"

	// EnvelopeMaxBytes bounds one envelope before it is decoded.
	EnvelopeMaxBytes = 1 << 20

	// envelopePrincipalMaxBytes bounds one principal name: a DNS label, so a
	// host can carry it wherever it carries a module principal.
	envelopePrincipalMaxBytes = 63
)

var (
	// ErrEnvelopeInvalid means a document violates the envelope's rules.
	ErrEnvelopeInvalid = errors.New("module envelope is invalid")

	// ErrEnvelopeStaleRevision means an envelope declares a revision lower than
	// the one delivered to its host. It is refused, never merged.
	ErrEnvelopeStaleRevision = errors.New("module envelope revision is older than the delivered revision")

	// ErrEnvelopeRewrittenRevision means the delivered revision came back with
	// different content. A revision is immutable; a change is a new one.
	ErrEnvelopeRewrittenRevision = errors.New("module envelope revision was rewritten")

	// ErrEnvelopeSignerNotRelease means an envelope verified under a key the
	// host pins as a person's. The grants a host holds for its module
	// principals are the composition's, delivered by its release pipeline; a
	// developer's own key may deliver a manifest it is pinned for, but never
	// widens what a module may do on a host.
	ErrEnvelopeSignerNotRelease = errors.New("module envelope is not signed by a release key")
)

// ModuleEnvelope is the authority grants a composition declares for one host,
// per module principal: the whole envelope, replaced as one document at each
// revision, never patched grant by grant.
//
// The grants belong to the host. Core owns the document around them — its
// schema, its canonical bytes, its signature, its revision — and reads each
// grant only as far as "a JSON object": what a grant may say is the host's
// contract, so a host can evolve it without a Core release, and Core cannot
// grow a second, drifting copy of it.
type ModuleEnvelope struct {
	Schema string `json:"schema"`

	// Host is the host the envelope is for and the ownership domain it speaks
	// for. The first delivered envelope's domain owns the host's envelope.
	Host HostTarget `json:"host"`

	// Revision starts at 1 and only rises for a host.
	Revision uint64 `json:"revision"`

	// Principals maps a module principal to its grant, a JSON object opaque to
	// Core. An empty map is an envelope that grants nothing: a composition
	// withdrawing every grant says so, rather than delivering nothing.
	Principals map[string]json.RawMessage `json:"principals"`
}

// Validate checks everything an envelope can be checked against on its own.
// Whether a revision may be applied over what a host holds is AdmitEnvelope's.
func (e *ModuleEnvelope) Validate() error {
	if e == nil {
		return fmt.Errorf("%w: an envelope is required", ErrEnvelopeInvalid)
	}
	if e.Schema != SchemaModuleEnvelopeV1 {
		return schemaRefusal(e.Schema, SchemaModuleEnvelopeV1)
	}
	switch {
	case !namePattern.MatchString(e.Host.Coordinate):
		return fmt.Errorf("%w: host coordinate %q is not a lowercase name", ErrEnvelopeInvalid, e.Host.Coordinate)
	case !namePattern.MatchString(e.Host.Domain):
		return fmt.Errorf("%w: ownership domain %q is not a lowercase name", ErrEnvelopeInvalid, e.Host.Domain)
	case e.Revision == 0:
		return fmt.Errorf("%w: revision starts at 1", ErrEnvelopeInvalid)
	case e.Principals == nil:
		// Absent and empty are different statements, and only one is a grant
		// of nothing; an absent map is a renderer that forgot the field.
		return fmt.Errorf("%w: principals is required; an envelope granting nothing writes {}", ErrEnvelopeInvalid)
	}
	for principal, grant := range e.Principals {
		if len(principal) > envelopePrincipalMaxBytes || !segmentPattern.MatchString(principal) {
			return fmt.Errorf("%w: principal %q is not one lowercase segment of at most %d bytes", ErrEnvelopeInvalid, principal, envelopePrincipalMaxBytes)
		}
		// json.Valid is what refuses a second value after the first; the
		// first byte is what refuses every value that is not an object.
		trimmed := bytes.TrimSpace(grant)
		if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
			return fmt.Errorf("%w: the grant for principal %q must be one JSON object", ErrEnvelopeInvalid, principal)
		}
	}
	return nil
}

// CanonicalBytes is the deterministic JSON encoding of a valid envelope:
// object keys in name order at every depth, inside the grants too, and every
// number its exact literal. It is what a signature covers and what Digest
// hashes, so a grant's own key order never moves it.
func (e *ModuleEnvelope) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return canonicalJSON(e)
}

// Digest is the SHA-256 of the canonical encoding, "sha256:<hex>". Two
// envelopes with one digest are one document.
func (e *ModuleEnvelope) Digest() (string, error) {
	canonical, err := e.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// EnvelopeFromVerified turns payload bytes the caller HAS ALREADY VERIFIED
// into an envelope. Like ManifestFromVerified it verifies no signature;
// VerifyDeliveredEnvelope is the entrypoint that does both.
//
// The decode is strict JSON — the envelope is only ever delivered in its
// canonical form, so there is no YAML to read — and the payload must then be
// byte for byte the envelope's canonical encoding. That round trip is also
// what refuses a repeated key at any depth, which encoding/json would
// otherwise resolve silently by keeping the last.
func EnvelopeFromVerified(payload []byte) (*ModuleEnvelope, error) {
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, fmt.Errorf("%w: no payload", errUnsignedEnvelope)
	}
	if len(payload) > EnvelopeMaxBytes {
		return nil, fmt.Errorf("%w: the document is %d bytes, more than the %d an envelope may hold", ErrEnvelopeInvalid, len(payload), EnvelopeMaxBytes)
	}
	// The schema first, so a manifest handed here is told it is the wrong
	// document rather than refused for a field it legitimately has.
	if schema := documentSchema(payload); schema != SchemaModuleEnvelopeV1 && json.Valid(payload) {
		return nil, schemaRefusal(schema, SchemaModuleEnvelopeV1)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var envelope ModuleEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("%w: decode module envelope: a field no envelope declares, or a value of the wrong shape: %v", ErrEnvelopeInvalid, err)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: decode module envelope: the payload holds more than one document", ErrEnvelopeInvalid)
		}
		return nil, fmt.Errorf("%w: decode module envelope: trailing input after the document: %v", ErrEnvelopeInvalid, err)
	}
	encoded, err := envelope.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, payload) {
		return nil, errEnvelopeNotCanonical
	}
	return &envelope, nil
}

// SchemaOf is the schema a payload declares, "" when it is not a JSON object
// declaring one. It dispatches; it validates nothing.
func SchemaOf(payload []byte) string {
	return documentSchema(payload)
}

// DeliveredEnvelope is an envelope whose carrier was verified against the
// host's pinned keys, signed by a release key pinned for its domain.
// VerifyDeliveredEnvelope is its only constructor. Like Delivered it keeps the
// attested bytes, and Envelope re-derives a fresh value on every call.
type DeliveredEnvelope struct {
	payload []byte
	signer  SignerIdentity
}

// Envelope re-derives the envelope from the attested bytes, fresh each call.
func (d *DeliveredEnvelope) Envelope() (*ModuleEnvelope, error) {
	return EnvelopeFromVerified(d.payload)
}

// Payload is the attested bytes, copied: what a host stores.
func (d *DeliveredEnvelope) Payload() []byte { return bytes.Clone(d.payload) }

// Signer is the verified key ID and its kind, read from the host's pins.
func (d *DeliveredEnvelope) Signer() SignerIdentity { return d.signer }

// VerifyDeliveredEnvelope verifies a carrier offline against the host's
// pinned keys — the verifier, carrier and domain pins the manifest uses — then
// checks the payload is a canonical envelope, that its signer is pinned as a
// release key (ErrEnvelopeSignerNotRelease), and that the signer is pinned for
// the ownership domain the envelope speaks for (ErrWrongDomain). Whether the
// revision may be applied over what the host holds is AdmitEnvelope's.
func VerifyDeliveredEnvelope(ctx context.Context, carrier *Signed, verifier *Verifier) (*DeliveredEnvelope, error) {
	if carrier == nil {
		return nil, fmt.Errorf("%w: no carrier", errUnsignedEnvelope)
	}
	if err := carrier.validate(); err != nil {
		return nil, err
	}
	if verifier == nil {
		return nil, fmt.Errorf("%w: no pinned-key verifier", errUnsignedEnvelope)
	}
	signer, err := verifier.VerifyEnvelope(ctx, carrier.Document, carrier.Envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: the attestation does not hold: %w", errUnsignedEnvelope, err)
	}
	envelope, err := EnvelopeFromVerified(carrier.Document)
	if err != nil {
		return nil, err
	}
	if signer.Kind != KeyKindRelease {
		return nil, fmt.Errorf("%w: pinned key %q is a %s key", ErrEnvelopeSignerNotRelease, signer.KeyID, signer.Kind)
	}
	if err := verifier.checkDomain(signer, envelope.Host.Domain); err != nil {
		return nil, err
	}
	return &DeliveredEnvelope{payload: bytes.Clone(carrier.Document), signer: signer}, nil
}

// AdmitEnvelope decides whether candidate may be applied by the host at
// coordinate, given the envelope previously DELIVERED to it (nil when none).
// It answers DecisionAccept or DecisionReplay, or refuses with:
//
//   - ErrEnvelopeInvalid: coordinate is not a host coordinate, or the
//     candidate is not a valid envelope;
//   - ErrWrongHost: the candidate targets another coordinate, or previous
//     was delivered to another one;
//   - ErrWrongDomain: the candidate speaks for another ownership domain than
//     the first delivered envelope did;
//   - ErrEnvelopeStaleRevision: a lower revision;
//   - ErrEnvelopeRewrittenRevision: the delivered revision with different
//     content;
//   - ErrAppliedUnusable: previous is not a valid envelope.
//
// It knows only delivered revisions. An envelope an administrator wrote on
// the host interactively is the host's state, and how a delivery compares to
// it is the host's decision.
func AdmitEnvelope(coordinate string, previous, candidate *ModuleEnvelope) (Decision, error) {
	if !namePattern.MatchString(coordinate) {
		return "", fmt.Errorf("%w: a host admits under its own coordinate, and %q is not one", ErrEnvelopeInvalid, coordinate)
	}
	if err := candidate.Validate(); err != nil {
		return "", err
	}
	if candidate.Host.Coordinate != coordinate {
		return "", fmt.Errorf("%w: the envelope targets %q, this host is %q", ErrWrongHost, candidate.Host.Coordinate, coordinate)
	}
	if previous == nil {
		return DecisionAccept, nil
	}
	if err := previous.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrAppliedUnusable, err)
	}
	if previous.Host.Coordinate != candidate.Host.Coordinate {
		return "", fmt.Errorf("%w: the delivered envelope is for %q and the candidate targets %q", ErrWrongHost, previous.Host.Coordinate, candidate.Host.Coordinate)
	}
	if previous.Host.Domain != candidate.Host.Domain {
		// Refused whatever the revision: otherwise any release key pinned for
		// any domain could replace a host's grants by declaring a higher one.
		return "", fmt.Errorf("%w: the host's envelope was delivered under domain %q and the candidate declares %q", ErrWrongDomain, previous.Host.Domain, candidate.Host.Domain)
	}
	switch {
	case candidate.Revision < previous.Revision:
		return "", fmt.Errorf("%w: the candidate is revision %d, delivered is %d", ErrEnvelopeStaleRevision, candidate.Revision, previous.Revision)
	case candidate.Revision > previous.Revision:
		return DecisionAccept, nil
	}
	delivered, err := previous.Digest()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAppliedUnusable, err)
	}
	digest, err := candidate.Digest()
	if err != nil {
		return "", err
	}
	if digest != delivered {
		return "", fmt.Errorf("%w: revision %d was delivered as %s and now reads %s", ErrEnvelopeRewrittenRevision, candidate.Revision, delivered, digest)
	}
	return DecisionReplay, nil
}
