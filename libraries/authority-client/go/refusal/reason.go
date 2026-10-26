// Package refusal defines caller-safe verifier failures. No reason retains a token,
// claim, key, transport error, or underlying error message.
package refusal

// Reason is a stable failure code with fixed, safe text.
type Reason string

const (
	Configuration   Reason = "configuration"
	StampProof      Reason = "stamp_proof"
	StampToken      Reason = "stamp_token"
	StampDigest     Reason = "stamp_digest"
	StampIdentity   Reason = "stamp_identity"
	StampMethod     Reason = "stamp_method"
	StampAudience   Reason = "stamp_audience"
	StampWindow     Reason = "stamp_window"
	StampAdvisory   Reason = "stamp_advisory"
	StampReplayed   Reason = "stamp_replayed"
	StampStore      Reason = "stamp_store"
	KeysUnavailable Reason = "keys_unavailable"
	Cancelled       Reason = "cancelled"
	Malformed       Reason = "malformed"
	Lifetime        Reason = "lifetime"
	Issuer          Reason = "issuer"
	UnknownKey      Reason = "unknown_key"
	InvalidKey      Reason = "invalid_key"
	FixtureKey      Reason = "fixture_key"
	Signature       Reason = "signature"
	Audience        Reason = "audience"
	NotYetValid     Reason = "not_yet_valid"
	Expired         Reason = "expired"
	Attenuation     Reason = "attenuation"
	Grant           Reason = "grant"
)

func (r Reason) Code() string  { return string(r) }
func (r Reason) Error() string { return r.Code() + ": " + r.Text() }
func (r Reason) Text() string {
	switch r {
	case Configuration:
		return "the verifier configuration is incomplete"
	case StampProof:
		return "the call carries no hop admission signed for it"
	case StampToken:
		return "the stamp binds no single Work Context"
	case StampDigest:
		return "the Work Context does not match the hop stamp"
	case StampIdentity:
		return "the stamp does not match the authenticated Work Context"
	case StampMethod:
		return "the hop admission was signed for another procedure"
	case StampAudience:
		return "the hop admission was signed for another module"
	case StampWindow:
		return "the hop admission is expired or outside its validity window"
	case StampAdvisory:
		return "an advisory policy refusal cannot admit a call"
	case StampReplayed:
		return "the hop admission has already been used"
	case StampStore:
		return "the hop admission store is unavailable"
	case KeysUnavailable:
		return "the authority's published keys are unavailable"
	case Cancelled:
		return "the call ended while the authority's keys were being read"
	case Malformed:
		return "the Work Context encoding or claims are invalid"
	case Lifetime:
		return "the capability lifetime exceeds the allowed bound"
	case Issuer:
		return "the Work Context was issued by an untrusted issuer"
	case UnknownKey:
		return "no verification key is published for this Work Context"
	case InvalidKey:
		return "the authority's verification key is malformed"
	case FixtureKey:
		return "the conformance fixture key is refused"
	case Signature:
		return "the signature does not verify under the published key"
	case Audience:
		return "the Work Context was minted for another audience"
	case NotYetValid:
		return "the Work Context is not valid before its not-before instant"
	case Expired:
		return "the Work Context has expired"
	case Attenuation:
		return "the actor chain widens authority"
	case Grant:
		return "the grant structure is invalid"
	default:
		return "the Work Context was refused"
	}
}
