package hop

import "github.com/codefly-dev/authority/libraries/authority-client/go/refusal"

// Reason is a caller-safe refusal. Use errors.As to extract its Code and Text.
// Verifier errors retain no unsafe diagnostic cause.
type Reason = refusal.Reason

const (
	ReasonConfiguration   = refusal.Configuration
	ReasonStampProof      = refusal.StampProof
	ReasonStampToken      = refusal.StampToken
	ReasonStampDigest     = refusal.StampDigest
	ReasonStampIdentity   = refusal.StampIdentity
	ReasonKeysUnavailable = refusal.KeysUnavailable
	ReasonCancelled       = refusal.Cancelled
	ReasonMalformed       = refusal.Malformed
	ReasonLifetime        = refusal.Lifetime
	ReasonIssuer          = refusal.Issuer
	ReasonUnknownKey      = refusal.UnknownKey
	ReasonInvalidKey      = refusal.InvalidKey
	ReasonFixtureKey      = refusal.FixtureKey
	ReasonSignature       = refusal.Signature
	ReasonAudience        = refusal.Audience
	ReasonNotYetValid     = refusal.NotYetValid
	ReasonExpired         = refusal.Expired
	ReasonAttenuation     = refusal.Attenuation
	ReasonGrant           = refusal.Grant
)
