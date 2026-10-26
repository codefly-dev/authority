/** Caller-safe verifier failures, as Go's libraries/authority-client/go/refusal
 * and Python's authority_client.work_context.Reason define them. No reason
 * retains a token, claim, key, transport error or underlying message.
 *
 * This lives apart from work-context.ts so hop-call.ts can refuse with the same
 * codes without importing it back. */
export enum Reason {
  Configuration = "configuration",
  StampProof = "stamp_proof",
  StampToken = "stamp_token",
  StampDigest = "stamp_digest",
  StampIdentity = "stamp_identity",
  StampMethod = "stamp_method",
  StampAudience = "stamp_audience",
  StampWindow = "stamp_window",
  StampIssued = "stamp_issued",
  StampAdvisory = "stamp_advisory",
  StampReplayed = "stamp_replayed",
  StampStore = "stamp_store",
  KeysUnavailable = "keys_unavailable",
  Cancelled = "cancelled",
  Malformed = "malformed",
  Lifetime = "lifetime",
  Issuer = "issuer",
  UnknownKey = "unknown_key",
  InvalidKey = "invalid_key",
  FixtureKey = "fixture_key",
  Signature = "signature",
  Audience = "audience",
  NotYetValid = "not_yet_valid",
  Expired = "expired",
  Attenuation = "attenuation",
  Grant = "grant",
}
const reasonText: Record<Reason, string> = {
  [Reason.Configuration]: "the verifier configuration is incomplete",
  [Reason.StampProof]: "the call carries no hop admission signed for it",
  [Reason.StampToken]: "the stamp binds no single Work Context",
  [Reason.StampDigest]: "the Work Context does not match the hop stamp",
  [Reason.StampIdentity]: "the stamp does not match the authenticated Work Context",
  [Reason.StampMethod]: "the hop admission was signed for another procedure",
  [Reason.StampAudience]: "the hop admission was signed for another module",
  [Reason.StampWindow]: "the hop admission is expired or outside its validity window",
  [Reason.StampIssued]: "the hop admission is issued further ahead than the clock allowance",
  [Reason.StampAdvisory]: "an advisory policy refusal cannot admit a call",
  [Reason.StampReplayed]: "the hop admission has already been used",
  [Reason.StampStore]: "the hop admission store is unavailable",
  [Reason.KeysUnavailable]: "the authority's published keys are unavailable",
  [Reason.Cancelled]: "the call ended while the authority's keys were being read",
  [Reason.Malformed]: "the Work Context encoding or claims are invalid",
  [Reason.Lifetime]: "the capability lifetime exceeds the allowed bound",
  [Reason.Issuer]: "the Work Context was issued by an untrusted issuer",
  [Reason.UnknownKey]: "no verification key is published for this Work Context",
  [Reason.InvalidKey]: "the authority's verification key is malformed",
  [Reason.FixtureKey]: "the conformance fixture key is refused",
  [Reason.Signature]: "the signature does not verify under the published key",
  [Reason.Audience]: "the Work Context was minted for another audience",
  [Reason.NotYetValid]: "the Work Context is not valid before its not-before instant",
  [Reason.Expired]: "the Work Context has expired",
  [Reason.Attenuation]: "the actor chain widens authority",
  [Reason.Grant]: "the grant structure is invalid",
};
/** Fixed caller-safe code and text; never retains a diagnostic cause. */
export class Unauthenticated extends Error {
  override name = "Unauthenticated";
  readonly text: string;
  constructor(readonly code: Reason) {
    super(`${code}: ${reasonText[code]}`);
    this.text = reasonText[code];
  }
}
