package solutionhost_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

// Sign, write, read, verify: what a delivery Job or the CLI produces is what a
// host reads back, byte for byte, as the manifest that was signed.
func TestASignedManifestRoundTripsThroughItsCarrier(t *testing.T) {
	manifest := valid(t)
	payload, err := solutionhost.SignedPayload(manifest)
	require.NoError(t, err)
	envelope, err := solutionhost.SignEnvelope(payload, signerFor(t, testKeyID))
	require.NoError(t, err)
	carrier, err := solutionhost.Carrier(payload, envelope)
	require.NoError(t, err)
	written, err := solutionhost.MarshalSigned(carrier)
	require.NoError(t, err)

	read, err := solutionhost.ParseSigned(written)
	require.NoError(t, err)
	delivered, err := solutionhost.VerifyDelivered(context.Background(), read, testVerifier(t))
	require.NoError(t, err)
	require.Equal(t, payload, delivered.Payload())
	require.Equal(t, solutionhost.SignerIdentity{KeyID: testKeyID, Kind: solutionhost.KeyKindRelease}, delivered.Signer())
	got, err := delivered.Manifest()
	require.NoError(t, err)
	want, err := manifest.Digest()
	require.NoError(t, err)
	digest, err := got.Digest()
	require.NoError(t, err)
	require.Equal(t, want, digest)

	// A withdrawal is signed and verified the same way.
	_, err = solutionhost.VerifyDelivered(context.Background(), signedManifest(t, removed(t)), testVerifier(t))
	require.NoError(t, err)
}

func signedManifest(t *testing.T, manifest *solutionhost.ModuleManifest) *solutionhost.Signed {
	t.Helper()
	payload, err := solutionhost.SignedPayload(manifest)
	require.NoError(t, err)
	return signedWith(t, payload, signerFor(t, testKeyID))
}

func TestVerificationRefusesAnythingButAPinnedSignerForTheDomain(t *testing.T) {
	carrier := signedValid(t)
	payload := carrier.Document

	// Signed by a key the host does not pin.
	_, err := solutionhost.VerifyDelivered(context.Background(), signedWith(t, payload, signerFor(t, "stranger")), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)

	// Signed under the pinned key ID with another private key.
	_, err = solutionhost.VerifyDelivered(context.Background(), signedWith(t, payload, differentKey(t, testKeyID)), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)

	// Signed by the pinned key, for a domain the key is not pinned for: the
	// manifest asserts its domain, so the pin is what bounds it.
	otherDomain := verifierFor(t, pinFor(t, signerFor(t, testKeyID), solutionhost.KeyKindRelease, "other"))
	_, err = solutionhost.VerifyDelivered(context.Background(), carrier, otherDomain)
	require.ErrorIs(t, err, solutionhost.ErrWrongDomain)
	twoDomains := verifierFor(t, pinFor(t, signerFor(t, testKeyID), solutionhost.KeyKindRelease, "other", testDomain))
	_, err = solutionhost.VerifyDelivered(context.Background(), carrier, twoDomains)
	require.NoError(t, err)

	// No carrier, no verifier.
	_, err = solutionhost.VerifyDelivered(context.Background(), nil, testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	_, err = solutionhost.VerifyDelivered(context.Background(), carrier, nil)
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
}

// A signer cannot produce, and a carrier cannot hold, anything but a canonical
// manifest: a replaced document is refused at signing with the remedy, and a
// re-encoded payload is refused even though it parses.
func TestOnlyACanonicalManifestIsSignedOrCarried(t *testing.T) {
	canonical, err := valid(t).CanonicalBytes()
	require.NoError(t, err)

	old := strings.Replace(string(canonical), solutionhost.SchemaModuleManifestV1, "codefly/solution-host-binding/v4", 1)
	_, err = solutionhost.SignEnvelope([]byte(old), signerFor(t, testKeyID))
	require.ErrorIs(t, err, solutionhost.ErrSchema)
	require.ErrorContains(t, err, "re-render")

	var generic map[string]any
	require.NoError(t, json.Unmarshal(canonical, &generic))
	indented, err := json.MarshalIndent(generic, "", "  ")
	require.NoError(t, err)
	envelope, err := solutionhost.SignEnvelope(indented, signerFor(t, testKeyID))
	require.NoError(t, err, "the envelope signs bytes; the carrier is what insists they are canonical")
	_, err = solutionhost.Carrier(indented, envelope)
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	require.ErrorIs(t, err, solutionhost.ErrNotCanonical)

	// A carrier assembled by hand around the same bytes is still refused at
	// verification, where it matters.
	_, err = solutionhost.VerifyDelivered(context.Background(), &solutionhost.Signed{Document: indented, Envelope: envelope}, testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
}

func TestACarrierIsStrict(t *testing.T) {
	written, err := solutionhost.MarshalSigned(signedValid(t))
	require.NoError(t, err)
	for name, data := range map[string]string{
		"key material":    strings.Replace(string(written), `{"document"`, `{"publicKey":"x","document"`, 1),
		"no envelope":     strings.Replace(string(written), `"envelope"`, `"other"`, 1),
		"trailing object": string(written) + "{}",
		"not json":        "document: x",
	} {
		_, err := solutionhost.ParseSigned([]byte(data))
		require.ErrorIs(t, err, solutionhost.ErrUnsigned, name)
	}
	_, err = solutionhost.ParseSigned(append(written, '\n'))
	require.NoError(t, err, "trailing whitespace is not a second document")
}
