package solutionhost_test

import (
	"context"
	"os"
	"testing"

	"github.com/codefly-dev/authority/libraries/solutionhost/go"
	"github.com/stretchr/testify/require"
)

// A module's governing scopes reach the host on the manifest it verifies, so
// the signature covers them: a delivery that names another governing scope is
// another document.
func TestSourceGovernanceSurvivesSignedDelivery(t *testing.T) {
	manifest := valid(t)
	manifest.Authority.SourceGovernance = []string{"wiki.pages:write"}
	written, err := solutionhost.Marshal(manifest)
	require.NoError(t, err)
	read, err := solutionhost.Parse(written)
	require.NoError(t, err)
	payload, err := solutionhost.SignedPayload(read)
	require.NoError(t, err)
	require.Contains(t, string(payload), `"source_governance":["wiki.pages:write"]`)
	envelope, err := solutionhost.SignEnvelope(payload, signerFor(t, testKeyID))
	require.NoError(t, err)
	delivered, err := solutionhost.VerifyDelivered(context.Background(), &solutionhost.Signed{Document: payload, Envelope: envelope}, testVerifier(t))
	require.NoError(t, err)
	got, err := delivered.Manifest()
	require.NoError(t, err)
	require.Equal(t, []string{"wiki.pages:write"}, got.Authority.SourceGovernance)

	widened, err := solutionhost.Parse(payload)
	require.NoError(t, err)
	widened.Authority.SourceGovernance = []string{"wiki.pages:read"}
	widenedBytes, err := widened.CanonicalBytes()
	require.NoError(t, err)
	_, err = solutionhost.VerifyDelivered(context.Background(), &solutionhost.Signed{Document: widenedBytes, Envelope: envelope}, testVerifier(t))
	require.ErrorIs(t, err, solutionhost.ErrUnsigned, "a governing scope moved after signing is not what was signed")
}

// A manifest declaring no governance is byte for byte the manifest it was
// before the field existed, so no delivered digest moves.
func TestNoSourceGovernanceKeepsTheCanonicalBytes(t *testing.T) {
	want, err := os.ReadFile("testdata/legacy-installation-manifest.json")
	require.NoError(t, err)
	for _, governance := range [][]string{nil, {}} {
		manifest := valid(t)
		manifest.Authority.SourceGovernance = governance
		got, err := manifest.CanonicalBytes()
		require.NoError(t, err)
		require.Equal(t, string(want), string(got))
	}
}

func TestSourceGovernanceIsCanonicallySorted(t *testing.T) {
	manifest := valid(t)
	manifest.Authority.ResourceKinds = []string{"wiki.pages", "wiki.drafts"}
	manifest.Authority.SourceGovernance = []string{"wiki.pages:write", "wiki.drafts:write"}
	first, err := manifest.Digest()
	require.NoError(t, err)
	manifest.Authority.SourceGovernance = []string{"wiki.drafts:write", "wiki.pages:write"}
	second, err := manifest.Digest()
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestSourceGovernanceIsHeldToTheModulesOwnKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		governance []string
		refusal    string
	}{
		"not a scope":    {[]string{"wiki.pages"}, `scope "wiki.pages" is not <resource kind>:<action>`},
		"no action":      {[]string{"wiki.pages:"}, "is not <resource kind>:<action>"},
		"two colons":     {[]string{"wiki.pages:write:all"}, "is not <resource kind>:<action>"},
		"multi-line":     {[]string{"wiki.pages:write\nx"}, "is not <resource kind>:<action>"},
		"another's kind": {[]string{"documents:write"}, `"documents:write" names a kind the module does not declare`},
		"declared twice": {[]string{"wiki.pages:write", "wiki.pages:write"}, "declares source governance scope \"wiki.pages:write\" twice"},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := valid(t)
			manifest.Authority.SourceGovernance = tc.governance
			err := manifest.Validate()
			require.ErrorIs(t, err, solutionhost.ErrInvalid)
			require.ErrorContains(t, err, tc.refusal)
		})
	}
}
