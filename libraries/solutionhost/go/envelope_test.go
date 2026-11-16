package solutionhost_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

// validEnvelope grants two principals on the test host. The grants are the
// host's shape, not Core's: Core only insists each is a JSON object.
func validEnvelope(t *testing.T) *solutionhost.ModuleEnvelope {
	t.Helper()
	envelope := &solutionhost.ModuleEnvelope{
		Schema:   solutionhost.SchemaModuleEnvelopeV1,
		Host:     solutionhost.HostTarget{Coordinate: testCoordinate, Domain: testDomain},
		Revision: 3,
		Principals: map[string]json.RawMessage{
			"wiki":    json.RawMessage(`{"scopes": ["modelservice.profiles:invoke"], "audience": "modelservice"}`),
			"indexer": json.RawMessage(`{}`),
		},
	}
	require.NoError(t, envelope.Validate())
	return envelope
}

func envelopePayload(t *testing.T, envelope *solutionhost.ModuleEnvelope) []byte {
	t.Helper()
	payload, err := envelope.CanonicalBytes()
	require.NoError(t, err)
	return payload
}

// Sign, write, read, verify: what publish signs with the cell's release key is
// what the host reads back, byte for byte, as the envelope that was signed.
func TestASignedEnvelopeRoundTripsThroughTheManifestsCarrier(t *testing.T) {
	envelope := validEnvelope(t)
	payload := envelopePayload(t, envelope)
	signed, err := solutionhost.SignEnvelope(payload, signerFor(t, testKeyID))
	require.NoError(t, err)
	var wire map[string]any
	require.NoError(t, json.Unmarshal(signed, &wire))
	require.Equal(t, solutionhost.PayloadTypeModuleEnvelope, wire["payloadType"])

	carrier, err := solutionhost.Carrier(payload, signed)
	require.NoError(t, err)
	written, err := solutionhost.MarshalSigned(carrier)
	require.NoError(t, err)
	read, err := solutionhost.ParseSigned(written)
	require.NoError(t, err)

	delivered, err := solutionhost.VerifyDeliveredEnvelope(context.Background(), read, testVerifier(t))
	require.NoError(t, err)
	require.Equal(t, payload, delivered.Payload())
	require.Equal(t, solutionhost.SignerIdentity{KeyID: testKeyID, Kind: solutionhost.KeyKindRelease}, delivered.Signer())
	got, err := delivered.Envelope()
	require.NoError(t, err)
	want, err := envelope.Digest()
	require.NoError(t, err)
	digest, err := got.Digest()
	require.NoError(t, err)
	require.Equal(t, want, digest)
	require.Equal(t, solutionhost.SchemaModuleEnvelopeV1, solutionhost.SchemaOf(payload))

	// The value handed out is a copy: changing it changes nothing delivered.
	got.Principals["wiki"] = json.RawMessage(`{"scopes":["everything"]}`)
	again, err := delivered.Envelope()
	require.NoError(t, err)
	require.JSONEq(t, `{"audience":"modelservice","scopes":["modelservice.profiles:invoke"]}`, string(again.Principals["wiki"]))

	// An envelope granting nothing is a statement, and travels the same way.
	empty := validEnvelope(t)
	empty.Principals = map[string]json.RawMessage{}
	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), signedWith(t, envelopePayload(t, empty), signerFor(t, testKeyID)), testVerifier(t))
	require.NoError(t, err)
}

func TestAnEnvelopeIsAdmittedOnlyFromAPinnedReleaseKeyForItsDomain(t *testing.T) {
	payload := envelopePayload(t, validEnvelope(t))
	carrier := signedWith(t, payload, signerFor(t, testKeyID))

	// A person's key verifies the signature and is still refused: a developer
	// key never speaks for a host's authority grants.
	person := verifierFor(t, pinFor(t, signerFor(t, testKeyID), solutionhost.KeyKindPerson, testDomain))
	_, err := solutionhost.VerifyDeliveredEnvelope(context.Background(), carrier, person)
	require.ErrorIs(t, err, solutionhost.ErrEnvelopeSignerNotRelease)

	// A release key not pinned for the envelope's domain.
	otherDomain := verifierFor(t, pinFor(t, signerFor(t, testKeyID), solutionhost.KeyKindRelease, "other"))
	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), carrier, otherDomain)
	require.ErrorIs(t, err, solutionhost.ErrWrongDomain)

	// A key the host does not pin, and the pinned key ID over another key.
	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), signedWith(t, payload, signerFor(t, "stranger")), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), signedWith(t, payload, differentKey(t, testKeyID)), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)

	// No carrier, no verifier.
	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), nil, testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), carrier, nil)
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
}

// One carrier, two documents: each verifier accepts only its own, so a
// manifest can never be admitted as a host's grants, nor grants as presence.
func TestEachVerifierAcceptsOnlyItsOwnDocument(t *testing.T) {
	_, err := solutionhost.VerifyDeliveredEnvelope(context.Background(), signedValid(t), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrSchema)

	envelope := signedWith(t, envelopePayload(t, validEnvelope(t)), signerFor(t, testKeyID))
	_, err = solutionhost.VerifyDelivered(context.Background(), envelope, testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrSchema)
}

// DSSE signs the payload type with the payload. A genuine signature made under
// one document type is refused for the other, whichever label the envelope
// then carries.
func TestASignatureIsBoundToItsDocumentType(t *testing.T) {
	signer := signerFor(t, testKeyID)
	verifier := testVerifier(t)
	for name, tc := range map[string]struct {
		carrier  *solutionhost.Signed
		signedAs string
	}{
		"envelope signed as a manifest": {
			carrier:  signedWith(t, envelopePayload(t, validEnvelope(t)), signer),
			signedAs: solutionhost.PayloadTypeModuleManifest,
		},
		"manifest signed as an envelope": {
			carrier:  signedValid(t),
			signedAs: solutionhost.PayloadTypeModuleEnvelope,
		},
	} {
		t.Run(name, func(t *testing.T) {
			document := tc.carrier.Document
			message := []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(tc.signedAs), tc.signedAs, len(document), document))
			signature, err := signer.Sign(message)
			require.NoError(t, err)
			sig := base64.StdEncoding.EncodeToString(signature)

			// Labelled with the type it was signed under: the label disagrees
			// with the document's schema.
			labelled := changeEnvelope(t, tc.carrier, func(e *wireEnvelope) {
				e.PayloadType = tc.signedAs
				e.Signatures[0].Sig = sig
			})
			// Relabelled with the document's own type: the signature is over
			// the other type, so it does not verify.
			relabelled := changeEnvelope(t, tc.carrier, func(e *wireEnvelope) { e.Signatures[0].Sig = sig })
			for _, carrier := range []*solutionhost.Signed{labelled, relabelled} {
				_, err := solutionhost.VerifyDeliveredEnvelope(context.Background(), carrier, verifier)
				require.ErrorIs(t, err, solutionhost.ErrUnsigned)
				_, err = solutionhost.VerifyDelivered(context.Background(), carrier, verifier)
				require.ErrorIs(t, err, solutionhost.ErrUnsigned)
			}
		})
	}
}

// A payload that is not the canonical encoding of the envelope it decodes to
// is refused even under a genuine signature, as a manifest's is.
func TestOnlyACanonicalEnvelopeIsCarriedOrDelivered(t *testing.T) {
	canonical := string(envelopePayload(t, validEnvelope(t)))
	for name, payload := range map[string]string{
		"whitespace":             canonical[:1] + " " + canonical[1:],
		"top-level key order":    reorderTop(t, canonical),
		"grant key order":        strings.Replace(canonical, `{"audience":"modelservice","scopes":["modelservice.profiles:invoke"]}`, `{"scopes":["modelservice.profiles:invoke"],"audience":"modelservice"}`, 1),
		"duplicate top-level":    strings.Replace(canonical, `"revision":3`, `"revision":2,"revision":3`, 1),
		"duplicate key in grant": strings.Replace(canonical, `{"audience":"modelservice",`, `{"audience":"other","audience":"modelservice",`, 1),
		"trailing newline":       canonical + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, canonical, payload)
			_, err := solutionhost.EnvelopeFromVerified([]byte(payload))
			require.ErrorIs(t, err, solutionhost.ErrNotCanonical)

			signed, err := solutionhost.SignEnvelope([]byte(payload), signerFor(t, testKeyID))
			require.NoError(t, err, "the envelope signs bytes; the carrier is what insists they are canonical")
			_, err = solutionhost.Carrier([]byte(payload), signed)
			require.ErrorIs(t, err, solutionhost.ErrUnsigned)
			require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
			_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), &solutionhost.Signed{Document: []byte(payload), Envelope: signed}, testVerifier(t))
			require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
		})
	}

	for name, payload := range map[string]string{
		"unknown top-level field": strings.Replace(canonical, `"revision":3`, `"revision":3,"signer":"me"`, 1),
		"second document":         canonical + canonical,
		"not json":                "schema: codefly/module-envelope/v1",
		"too large":               canonical[:len(canonical)-1] + `,"pad":"` + strings.Repeat("x", solutionhost.EnvelopeMaxBytes) + `"}`,
	} {
		_, err := solutionhost.EnvelopeFromVerified([]byte(payload))
		require.ErrorIs(t, err, solutionhost.ErrEnvelopeInvalid, name)
	}

	// Neither document: the carrier says what it accepts.
	other := strings.Replace(canonical, solutionhost.SchemaModuleEnvelopeV1, "codefly/module-envelope/v2", 1)
	_, err := solutionhost.SignEnvelope([]byte(other), signerFor(t, testKeyID))
	require.ErrorIs(t, err, solutionhost.ErrSchema)
	require.ErrorContains(t, err, solutionhost.SchemaModuleEnvelopeV1)
	_, err = solutionhost.Carrier([]byte(other), json.RawMessage(`{"payloadType":"x"}`))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	require.ErrorIs(t, err, solutionhost.ErrSchema)
	_, err = solutionhost.EnvelopeFromVerified([]byte(other))
	require.ErrorIs(t, err, solutionhost.ErrSchema)
}

// reorderTop moves "schema" first, which is not name order.
func reorderTop(t *testing.T, canonical string) string {
	t.Helper()
	schema := `,"schema":"` + solutionhost.SchemaModuleEnvelopeV1 + `"`
	require.Contains(t, canonical, schema)
	return `{"schema":"` + solutionhost.SchemaModuleEnvelopeV1 + `",` + strings.Replace(canonical, schema, "", 1)[1:]
}

// A grant is opaque to Core, so canonicalisation must not reinterpret it: a
// number keeps its exact literal, however large.
func TestAGrantsNumbersSurviveCanonicalisation(t *testing.T) {
	envelope := validEnvelope(t)
	envelope.Principals["wiki"] = json.RawMessage(`{"quota": 12345678901234567890, "ratio": 1.50, "small": 1e-7}`)
	payload := envelopePayload(t, envelope)
	require.Contains(t, string(payload), `{"quota":12345678901234567890,"ratio":1.50,"small":1e-7}`)
	read, err := solutionhost.EnvelopeFromVerified(payload)
	require.NoError(t, err)
	require.Equal(t, `{"quota":12345678901234567890,"ratio":1.50,"small":1e-7}`, string(read.Principals["wiki"]))
}

func TestEnvelopeValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*solutionhost.ModuleEnvelope)
		want   error
	}{
		"wrong schema":         {func(e *solutionhost.ModuleEnvelope) { e.Schema = solutionhost.SchemaModuleManifestV1 }, solutionhost.ErrSchema},
		"no schema":            {func(e *solutionhost.ModuleEnvelope) { e.Schema = "" }, solutionhost.ErrSchema},
		"bad coordinate":       {func(e *solutionhost.ModuleEnvelope) { e.Host.Coordinate = "Obin/Local" }, solutionhost.ErrEnvelopeInvalid},
		"no coordinate":        {func(e *solutionhost.ModuleEnvelope) { e.Host.Coordinate = "" }, solutionhost.ErrEnvelopeInvalid},
		"bad domain":           {func(e *solutionhost.ModuleEnvelope) { e.Host.Domain = "obin domain" }, solutionhost.ErrEnvelopeInvalid},
		"zero revision":        {func(e *solutionhost.ModuleEnvelope) { e.Revision = 0 }, solutionhost.ErrEnvelopeInvalid},
		"nil principals":       {func(e *solutionhost.ModuleEnvelope) { e.Principals = nil }, solutionhost.ErrEnvelopeInvalid},
		"path principal":       {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki/admin"] = json.RawMessage(`{}`) }, solutionhost.ErrEnvelopeInvalid},
		"uppercase principal":  {func(e *solutionhost.ModuleEnvelope) { e.Principals["Wiki"] = json.RawMessage(`{}`) }, solutionhost.ErrEnvelopeInvalid},
		"empty principal":      {func(e *solutionhost.ModuleEnvelope) { e.Principals[""] = json.RawMessage(`{}`) }, solutionhost.ErrEnvelopeInvalid},
		"64-byte principal":    {func(e *solutionhost.ModuleEnvelope) { e.Principals[strings.Repeat("a", 64)] = json.RawMessage(`{}`) }, solutionhost.ErrEnvelopeInvalid},
		"string grant":         {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = json.RawMessage(`"all"`) }, solutionhost.ErrEnvelopeInvalid},
		"array grant":          {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = json.RawMessage(`[{}]`) }, solutionhost.ErrEnvelopeInvalid},
		"null grant":           {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = json.RawMessage(`null`) }, solutionhost.ErrEnvelopeInvalid},
		"absent grant":         {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = nil }, solutionhost.ErrEnvelopeInvalid},
		"two objects in grant": {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = json.RawMessage(`{}{}`) }, solutionhost.ErrEnvelopeInvalid},
		"broken grant":         {func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = json.RawMessage(`{"a":`) }, solutionhost.ErrEnvelopeInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			envelope := validEnvelope(t)
			tc.change(envelope)
			require.ErrorIs(t, envelope.Validate(), tc.want)
			_, err := envelope.CanonicalBytes()
			require.ErrorIs(t, err, tc.want)
		})
	}

	envelope := validEnvelope(t)
	envelope.Principals[strings.Repeat("a", 63)] = json.RawMessage(` {"padded": true} `)
	require.NoError(t, envelope.Validate(), "63 bytes is a principal, and whitespace around one object is still one object")
	var none *solutionhost.ModuleEnvelope
	require.ErrorIs(t, none.Validate(), solutionhost.ErrEnvelopeInvalid)
}

func TestAdmitEnvelope(t *testing.T) {
	at := func(revision uint64, change ...func(*solutionhost.ModuleEnvelope)) *solutionhost.ModuleEnvelope {
		envelope := validEnvelope(t)
		envelope.Revision = revision
		for _, c := range change {
			c(envelope)
		}
		return envelope
	}
	regrant := func(e *solutionhost.ModuleEnvelope) { e.Principals["wiki"] = json.RawMessage(`{"scopes":[]}`) }
	reordered := func(e *solutionhost.ModuleEnvelope) {
		e.Principals["wiki"] = json.RawMessage(`{"audience":"modelservice","scopes":["modelservice.profiles:invoke"]}`)
	}
	elsewhere := func(e *solutionhost.ModuleEnvelope) { e.Host.Coordinate = "obin/local/other" }
	otherDomain := func(e *solutionhost.ModuleEnvelope) { e.Host.Domain = "other" }

	for name, tc := range map[string]struct {
		coordinate          string
		previous, candidate *solutionhost.ModuleEnvelope
		want                solutionhost.Decision
		err                 error
	}{
		"first delivery":                     {testCoordinate, nil, at(1), solutionhost.DecisionAccept, nil},
		"replay":                             {testCoordinate, at(3), at(3), solutionhost.DecisionReplay, nil},
		"replay in another key order":        {testCoordinate, at(3), at(3, reordered), solutionhost.DecisionReplay, nil},
		"rewritten revision":                 {testCoordinate, at(3), at(3, regrant), "", solutionhost.ErrEnvelopeRewrittenRevision},
		"stale revision":                     {testCoordinate, at(3), at(2), "", solutionhost.ErrEnvelopeStaleRevision},
		"higher revision":                    {testCoordinate, at(3), at(4, regrant), solutionhost.DecisionAccept, nil},
		"candidate for another host":         {testCoordinate, nil, at(1, elsewhere), "", solutionhost.ErrWrongHost},
		"previous for another host":          {"obin/local/other", at(3), at(4, elsewhere), "", solutionhost.ErrWrongHost},
		"domain change, even higher":         {testCoordinate, at(3), at(9, otherDomain), "", solutionhost.ErrWrongDomain},
		"not a coordinate":                   {"Not A Host", nil, at(1), "", solutionhost.ErrEnvelopeInvalid},
		"invalid candidate":                  {testCoordinate, nil, at(0), "", solutionhost.ErrEnvelopeInvalid},
		"no candidate":                       {testCoordinate, at(3), nil, "", solutionhost.ErrEnvelopeInvalid},
		"invalid previous":                   {testCoordinate, at(0), at(1), "", solutionhost.ErrAppliedUnusable},
		"previous with an unreadable schema": {testCoordinate, at(3, func(e *solutionhost.ModuleEnvelope) { e.Schema = "x" }), at(4), "", solutionhost.ErrAppliedUnusable},
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := solutionhost.AdmitEnvelope(tc.coordinate, tc.previous, tc.candidate)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				require.Empty(t, decision)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, decision)
		})
	}
}

// A refusal names the document it refused: an envelope's never reads as a
// manifest's, nor a manifest's as an envelope's, and both still match the
// sentinel a caller tests for.
func TestARefusalNamesTheDocumentItRefused(t *testing.T) {
	stranger := func(payload []byte) *solutionhost.Signed { return signedWith(t, payload, signerFor(t, "stranger")) }
	envelopePayload, err := validEnvelope(t).CanonicalBytes()
	require.NoError(t, err)
	manifestPayload := signedValid(t).Document

	_, err = solutionhost.VerifyDeliveredEnvelope(context.Background(), stranger(envelopePayload), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	require.ErrorContains(t, err, "module envelope is not a signed document")
	require.NotContains(t, err.Error(), "manifest")

	_, err = solutionhost.VerifyDelivered(context.Background(), stranger(manifestPayload), testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned)
	require.ErrorContains(t, err, "module manifest is not a signed document")
	require.NotContains(t, err.Error(), "envelope is not")

	_, err = solutionhost.EnvelopeFromVerified(append(envelopePayload, ' '))
	require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
	require.ErrorContains(t, err, "module envelope payload")
	_, err = solutionhost.ManifestFromVerified(append(manifestPayload, ' '))
	require.ErrorIs(t, err, solutionhost.ErrNotCanonical)
	require.ErrorContains(t, err, "module manifest payload")
}
