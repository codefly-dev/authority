import { createHash, createPublicKey, verify } from "node:crypto";

/** Durable atomic consumption, shared by all replicas. Throw Replayed on reuse, another error on outage.
 * retainUntil is Unix seconds. Successful reservations must survive restart. */
export class Replayed extends Error { override name = "Replayed"; }

export interface ReplayStore { consume(nonce: string, retainUntil: number): Promise<void>; }

export function checkCall(pairs: readonly (readonly [string, string])[], publicKey: string, method: string, audience: string, now: number): { nonce: string; expires: number } {
  const fail = (reason: string): never => { throw new Error(`hop: ${reason}`); };
  const one = (key: string): string => { const values = pairs.filter(([k]) => k === key); return values.length === 1 ? values[0][1] : ""; };
  const encoded = one("x-codefly-hop-proof"), parts = encoded.split(".");
  if (!/^[0-9a-f]{64}$/.test(publicKey) || parts.length !== 2 || encoded.length > 8192) fail("invalid signed hop proof");
  const decode = (part: string): Buffer => {
    const raw = Buffer.from(part, "base64url");
    if (!/^[A-Za-z0-9_-]+$/.test(part) || raw.toString("base64url") !== part) fail("noncanonical hop proof");
    return raw;
  };
  const payload = decode(parts[0]), signature = decode(parts[1]);
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey, "hex").toString("base64url") }, format: "jwk" });
  if (!verify(null, payload, key, signature)) fail("hop proof signature does not verify");
  let fields: unknown;
  try { fields = JSON.parse(payload.toString("utf8")); } catch { fail("malformed hop proof"); }
  if (!Array.isArray(fields) || fields.length !== 7) return fail("malformed hop proof");
  const [domain, boundMethod, boundAudience, digest, nonce, issued, expires] = fields;
  if (!fields.slice(0, 5).every(v => typeof v === "string") || !Number.isSafeInteger(issued) || !Number.isSafeInteger(expires)) fail("malformed hop proof fields");
  if (domain !== "codefly-hop-v1") fail("unknown hop proof version");
  if (!method || method !== boundMethod) fail("hop proof method mismatch");
  if (!audience || audience !== boundAudience) fail("hop proof audience mismatch");
  const seconds = Math.floor(now / 1000);
  if (issued < 0 || expires < 0 || issued > seconds || expires <= seconds || expires <= issued || expires - issued > 30) fail("hop proof expired or outside its validity window");
  if (!/^[0-9a-f]{64}$/.test(nonce)) fail("invalid hop proof nonce");
  const token = one("x-codefly-work-context");
  if (!token || digest !== createHash("sha256").update(token).digest("hex") || digest !== one("x-codefly-hop-context")) fail("hop proof token digest mismatch");
  if (pairs.some(([key]) => key === "x-codefly-hop-advisory")) fail("hop proof cannot authorize an advisory refusal");
  return { nonce: `codefly-hop-v1:${publicKey}:${nonce}`, expires };
}
