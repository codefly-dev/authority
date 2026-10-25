/** Authenticate the Work Context the hop forwarded to a Node module, then project it.
 *
 * `authenticateClaims` is the Go library's `workcontext.Authenticate`, check for
 * check where it matters: the stamp binds exactly one token to this run's proof by
 * its digest, and the token itself must carry a valid Ed25519 signature under the
 * authority's published key, name the pinned issuer, be addressed to this module and
 * be inside its window, judged in Core's order. Core's structural and attenuation
 * rules constrain what the authority signs and are not reproduced. Nothing here asks
 * the authority or consumes a nonce: liveness is the hop's Check, which the digest
 * binds to this call. */
import { createHash, createPublicKey, timingSafeEqual, verify, type KeyObject } from "node:crypto";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import type { KeysResponse } from "./src/gen/host/authority/v1/authority_pb.js";
import { WorkContextV1Schema, type WorkContextV1 } from "./src/gen/host/authority/v1/work_context_pb.js";

/** Core's bounds: MaxTokenSize, DefaultSkew, MaxTTLCeiling. */
const MAX_TOKEN_BYTES = 32 * 1024, SKEW_SECONDS = 30, MAX_LIFETIME_SECONDS = 24 * 3600;

export class Unauthenticated extends Error {
  override name = "Unauthenticated";
}

/** The authority a module believes: its issuer and published keys, from Keys. */
export interface Trust {
  readonly issuer: string;
  readonly keys: ReadonlyMap<string, KeyObject>;
  /** Unix milliseconds; Date.now when omitted. */
  readonly now?: () => number;
}

/** Trust from the authority interface's KeysResponse: Ed25519 keys only. */
export function trustFromKeys(response: KeysResponse, now?: () => number): Trust {
  const keys = new Map<string, KeyObject>();
  for (const key of response.keys) {
    if (key.algorithm !== "Ed25519") continue;
    if (!key.keyId || keys.has(key.keyId) || key.publicKey.length !== 32) {
      throw new Unauthenticated("the authority publishes an unnamed, repeated or malformed key");
    }
    keys.set(key.keyId, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(key.publicKey).toString("base64url") }, format: "jwk" }));
  }
  if (!response.issuer || keys.size === 0) throw new Unauthenticated("the authority publishes no issuer or no Ed25519 key");
  return { issuer: response.issuer, keys, now };
}

export interface Scope {
  readonly resourceKind: string;
  readonly actions: readonly string[];
  readonly resourceIds: readonly string[];
}

export interface Claims {
  readonly audience: string;
  readonly scopes: readonly Scope[];
  /** The authenticated claims, whole. */
  readonly context: WorkContextV1;
  /** Empty resourceID asks for the entire kind. Actions and IDs are literal. */
  allows(kind: string, action: string, resourceID?: string): boolean;
}

/** Server-side request headers; repeated values must not be discarded. */
export type StampHeaders = Readonly<Record<string, string | readonly string[]>> | Iterable<readonly [string, string]>;

/** The claims of the Work Context the hop forwarded to this module (audience), or
 * Unauthenticated naming why it must not be believed. */
export function authenticateClaims(headers: StampHeaders, proof: string, audience: string, trust: Trust): Claims {
  if (!audience) throw new Unauthenticated("no audience: a module authenticates a context for itself");
  const token = boundToken(headers, proof);
  if (token.length > MAX_TOKEN_BYTES || token.split(".").length !== 2) {
    throw new Unauthenticated("expected a bounded payload.signature context");
  }
  const [payloadSegment, signatureSegment] = token.split(".");
  const payload = decodeSegment(payloadSegment), signature = decodeSegment(signatureSegment);
  let context: WorkContextV1;
  try {
    context = fromBinary(WorkContextV1Schema, payload, { readUnknownFields: false });
  } catch {
    throw new Unauthenticated("payload is not a WorkContextV1");
  }
  const canonical = toBinary(WorkContextV1Schema, context);
  if (canonical.length !== payload.length || canonical.some((byte, index) => byte !== payload[index])) {
    throw new Unauthenticated("payload is noncanonical or carries a field this reader does not know");
  }
  if (context.algorithm !== "Ed25519") throw new Unauthenticated(`algorithm ${context.algorithm} is not Ed25519`);
  if (context.issuer !== trust.issuer) throw new Unauthenticated(`issued by ${context.issuer}, not ${trust.issuer}`);
  const key = trust.keys.get(context.keyId);
  if (!key) throw new Unauthenticated(`no verification key ${context.keyId}; the authority does not publish it`);
  if (signature.length !== 64 || !verify(null, payload, key, signature)) {
    throw new Unauthenticated("signature does not verify under the authority's published key");
  }
  if (context.audience !== audience) throw new Unauthenticated(`minted for audience ${context.audience}, presented to ${audience}`);
  const now = (trust.now ?? Date.now)() / 1000, notBefore = Number(context.notBeforeUnix), expires = Number(context.expiresAtUnix);
  if (expires - notBefore > MAX_LIFETIME_SECONDS) throw new Unauthenticated("lifetime exceeds 24h");
  if (now + SKEW_SECONDS < notBefore) throw new Unauthenticated("not valid before its not-before instant");
  if (!(now - SKEW_SECONDS < expires)) throw new Unauthenticated("expired");
  const effective = context.actorChain.at(-1)?.grantedScopes ?? context.authorityScopes;
  const scopes = Object.freeze(effective.map(scope => Object.freeze({
    resourceKind: scope.resourceKind,
    actions: Object.freeze([...scope.actions]),
    resourceIds: Object.freeze([...scope.resourceIds]),
  })));
  return Object.freeze({
    audience: context.audience,
    scopes,
    context,
    allows(kind: string, action: string, resourceID = ""): boolean {
      if (!kind || !action) return false;
      return scopes.some(scope => scope.resourceKind === kind && scope.actions.includes(action) &&
        (scope.resourceIds.length === 0 || (resourceID !== "" && scope.resourceIds.includes(resourceID))));
    },
  });
}

/** The one token the stamp's digest binds under this run's proof. Bound, not
 * authenticated: whoever holds the proof can write both. */
function boundToken(headers: StampHeaders, proof: string): string {
  if (headers === null || typeof headers !== "object" || typeof proof !== "string") {
    throw new Unauthenticated("context requires request headers and a run proof");
  }
  const values = new Map<string, string[]>();
  const pairs = Symbol.iterator in Object(headers) ? headers as Iterable<readonly [string, string]> : Object.entries(headers);
  for (const [key, value] of pairs) {
    const name = key.toLowerCase();
    values.set(name, [...(values.get(name) ?? []), ...(typeof value === "string" ? [value] : value)]);
  }
  const one = (key: string): string => { const v = values.get(key); return v?.length === 1 ? v[0] : ""; };
  const equal = (a: string, b: string): boolean => {
    const left = new TextEncoder().encode(a), right = new TextEncoder().encode(b);
    return left.length === right.length && timingSafeEqual(left, right);
  };
  const token = one("x-codefly-work-context");
  if (!proof || !equal(proof, one("x-codefly-hop-proof"))) {
    throw new Unauthenticated("the call did not come through the hop: it carries no stamp with this run's proof");
  }
  if (!token || !equal(createHash("sha256").update(token).digest("hex"), one("x-codefly-hop-context"))) {
    throw new Unauthenticated("the Work Context is not the one the hop's stamp binds");
  }
  return token;
}

function decodeSegment(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Unauthenticated("context segment is not base64url");
  const decoded = Buffer.from(segment, "base64url");
  if (decoded.toString("base64url") !== segment) throw new Unauthenticated("context segment is not canonical base64url");
  return new Uint8Array(decoded);
}
