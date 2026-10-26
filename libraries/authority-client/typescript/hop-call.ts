import { createHash, createPublicKey, verify } from "node:crypto";
import { Reason, Unauthenticated } from "./refusal.js";

/** The hop admission lifetime and the clock allowance, as Go's stamp.Lifetime
 * and stamp.Skew define them, in seconds. An admission may be issued up to SKEW
 * ahead of this verifier's clock and stays admissible until SKEW past its
 * expiry; the signed span is still capped at LIFETIME exactly. */
export const LIFETIME = 30, SKEW = 2;

/** Durable atomic consumption, shared by all replicas. Throw Replayed on reuse, another error on outage.
 * retainUntil is Unix seconds. Successful reservations must survive restart. */
export class Replayed extends Error { override name = "Replayed"; }

/** The reservation's retention had already passed when the store decided. */
export class Expired extends Error { override name = "Expired"; }

export interface ReplayStore {
  /** True only for the durable store every replica shares; required outside local. */
  readonly shared?: boolean;
  consume(nonce: string, retainUntil: number): Promise<void>;
  /** A reservation store holds a single-use admission while the call carrying
   * it runs: the verifier reserves when the call arrives and finishes when its
   * handler has returned, and the store keeps the reservation until finish AND
   * retainUntil have both passed. reserve refuses atomically, across every
   * replica, a nonce already held (Replayed), including one held by a call still
   * running past its retention, and refuses a reservation whose retainUntil has
   * already passed by the store's clock (Expired), so a delayed reservation
   * never revives a collected nonce. A finish that fails leaves it held. */
  reserve?(nonce: string, retainUntil: number): Promise<void>;
  finish?(nonce: string): Promise<void>;
}

export function checkCall(pairs: readonly (readonly [string, string])[], publicKey: string, method: string, audience: string, now: number): { nonce: string; expires: number } {
  const fail = (reason: Reason): never => { throw new Unauthenticated(reason); };
  const one = (key: string): string => { const values = pairs.filter(([k]) => k === key); return values.length === 1 ? values[0][1] : ""; };
  const encoded = one("x-codefly-hop-proof"), parts = encoded.split(".");
  if (!/^[0-9a-f]{64}$/.test(publicKey) || parts.length !== 2 || encoded.length > 8192) fail(Reason.StampProof);
  const decode = (part: string): Buffer => {
    const raw = Buffer.from(part, "base64url");
    if (!/^[A-Za-z0-9_-]+$/.test(part) || raw.toString("base64url") !== part) fail(Reason.StampProof);
    return raw;
  };
  const payload = decode(parts[0]), signature = decode(parts[1]);
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey, "hex").toString("base64url") }, format: "jwk" });
  if (!verify(null, payload, key, signature)) fail(Reason.StampProof);
  let fields: unknown;
  try { fields = JSON.parse(payload.toString("utf8")); } catch { fail(Reason.StampProof); }
  if (!Array.isArray(fields) || fields.length !== 7) return fail(Reason.StampProof);
  const [domain, boundMethod, boundAudience, digest, nonce, issued, expires] = fields;
  if (!fields.slice(0, 5).every(v => typeof v === "string") || !Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) fail(Reason.StampProof);
  if (domain !== "codefly-hop-v1") fail(Reason.StampProof);
  if (!method || method !== boundMethod) fail(Reason.StampMethod);
  if (!audience || audience !== boundAudience) fail(Reason.StampAudience);
  const seconds = Math.floor(now / 1000);
  if (issued < 0 || expires < 0) fail(Reason.StampWindow);
  if (issued > seconds + SKEW) fail(Reason.StampIssued);
  if (expires + SKEW <= seconds || expires <= issued || expires - issued > LIFETIME) fail(Reason.StampWindow);
  if (!/^[0-9a-f]{64}$/.test(nonce)) fail(Reason.StampProof);
  const tokens = pairs.filter(([k]) => k === "x-codefly-work-context");
  if (tokens.length !== 1 || !tokens[0][1]) fail(Reason.StampToken);
  const token = tokens[0][1];
  if (digest !== createHash("sha256").update(token).digest("hex") || digest !== one("x-codefly-hop-context")) fail(Reason.StampDigest);
  if (pairs.some(([key]) => key === "x-codefly-hop-advisory")) fail(Reason.StampAdvisory);
  return { nonce: `codefly-hop-v1:${publicKey}:${nonce}`, expires };
}
