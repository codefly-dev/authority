package solutionhost

import (
	"bytes"
	"context"
	"fmt"
)

// Delivered is a manifest whose carrier was verified against the host's pinned
// keys, together with the signer that was attested. VerifyDelivered is its
// only constructor, so holding one means the verifier ran.
//
// It stores the ATTESTED BYTES rather than a parsed manifest, and Manifest
// re-derives a fresh value from them on every call: a caller normalising the
// manifest it was handed cannot change what the host applies or the digest it
// stores.
type Delivered struct {
	payload []byte
	signer  SignerIdentity
}

// Manifest re-derives the manifest from the attested bytes, fresh each call.
func (d *Delivered) Manifest() (*ModuleManifest, error) {
	return ManifestFromVerified(d.payload)
}

// Payload is the attested bytes, copied: what a host stores.
func (d *Delivered) Payload() []byte { return bytes.Clone(d.payload) }

// Signer is the verified key ID and its kind, read from the host's pins.
func (d *Delivered) Signer() SignerIdentity { return d.signer }

// VerifyDelivered verifies a carrier offline against the host's pinned keys,
// then checks the payload is a canonical manifest and that the signer is
// pinned for the ownership domain the manifest speaks for (ErrWrongDomain).
// It returns nothing unless all three hold. Whether the manifest may be
// applied over what the host holds is Admit's.
func VerifyDelivered(ctx context.Context, carrier *Signed, verifier *Verifier) (*Delivered, error) {
	if carrier == nil {
		return nil, fmt.Errorf("%w: no carrier", errUnsignedManifest)
	}
	if err := carrier.validate(); err != nil {
		return nil, err
	}
	if verifier == nil {
		return nil, fmt.Errorf("%w: no pinned-key verifier", errUnsignedManifest)
	}
	signer, err := verifier.VerifyEnvelope(ctx, carrier.Document, carrier.Envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: the attestation does not hold: %w", errUnsignedManifest, err)
	}
	manifest, err := ManifestFromVerified(carrier.Document)
	if err != nil {
		return nil, err
	}
	if err := verifier.checkDomain(signer, manifest.Host.Domain); err != nil {
		return nil, err
	}
	return &Delivered{payload: bytes.Clone(carrier.Document), signer: signer}, nil
}
