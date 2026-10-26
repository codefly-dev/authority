import { createHash, createPublicKey, verify } from "node:crypto";
import type { KeysResponse } from "./src/gen/host/authority/v1/authority_pb.js";
import { Reason, Unauthenticated } from "./refusal.js";

/** What a published admission key verifies: Keys carries the hop's keys in
 * admission_keys with this purpose, never among the Work Context keys. */
export const PURPOSE = "hop-admission";

/** The hop admission keys a KeysResponse publishes, hex: Ed25519 keys in
 * admissionKeys with purpose PURPOSE; anything else there is not one. */
export function admissionKeys(response: KeysResponse): string[] {
  const out: string[] = [];
  for (const key of response.admissionKeys) {
    if (key.algorithm !== "Ed25519" || key.purpose !== PURPOSE) continue;
    if (key.publicKey.length !== 32) throw new Unauthenticated(Reason.InvalidKey);
    const hex = Buffer.from(key.publicKey).toString("hex");
    if (!out.includes(hex)) out.push(hex);
  }
  return out;
}

/** The one admission the headers carry, as its signed payload and signature,
 * each in canonical encoding; undefined for anything else. */
function proof(pairs: readonly (readonly [string, string])[]): { payload: Buffer; signature: Buffer } | undefined {
  const values = pairs.filter(([k]) => k === "x-codefly-hop-proof");
  if (values.length !== 1 || values[0][1].length > 8192) return undefined;
  const parts = values[0][1].split(".");
  if (parts.length !== 2) return undefined;
  const raw = parts.map(part => /^[A-Za-z0-9_-]+$/.test(part) ? Buffer.from(part, "base64url") : undefined);
  if (raw.some((r, i) => !r || r.toString("base64url") !== parts[i])) return undefined;
  return { payload: raw[0]!, signature: raw[1]! };
}

const ed25519 = (hex: string) => createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(hex, "hex").toString("base64url") }, format: "jwk" });

/** Which published admission key (hex) the admission is signed by, or "" for
 * none: Go's stamp.SignedBy. checkCall, given that key, judges the rest. */
export function signedBy(pairs: readonly (readonly [string, string])[], publicKeys: readonly string[]): string {
  const signed = proof(pairs);
  if (!signed) return "";
  for (const key of publicKeys) {
    if (/^[0-9a-f]{64}$/.test(key) && verify(null, signed.payload, ed25519(key), signed.signature)) return key;
  }
  return "";
}

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
   * never revives a collected nonce. A finish that fails leaves it held.
   * Because reserve refuses past retainUntil on the store's clock, a store may
   * collect a reservation once that has passed, finished or not. */
  reserve?(nonce: string, retainUntil: number): Promise<void>;
  finish?(nonce: string): Promise<void>;
}

export function checkCall(pairs: readonly (readonly [string, string])[], publicKey: string, method: string, audience: string, now: number): { nonce: string; expires: number } {
  const fail = (reason: Reason): never => { throw new Unauthenticated(reason); };
  const one = (key: string): string => { const values = pairs.filter(([k]) => k === key); return values.length === 1 ? values[0][1] : ""; };
  const signed = proof(pairs);
  if (!/^[0-9a-f]{64}$/.test(publicKey) || !signed || !verify(null, signed.payload, ed25519(publicKey), signed.signature)) return fail(Reason.StampProof);
  const { payload } = signed;
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
