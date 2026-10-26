import { checkCall, Replayed, type ReplayStore } from "./hop-call.js";
export { Replayed } from "./hop-call.js";
export type { ReplayStore } from "./hop-call.js";
/** Work Context identity readers and method-bound, single-use hop admission.
 * Verifier consumes signed call nonces in a required durable shared ReplayStore.
 * authenticateClaims alone authenticates identity, not admission. */
import { createHash, createPrivateKey, createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { equals, fromBinary, toBinary } from "@bufbuild/protobuf";
import { createValidator } from "@bufbuild/protovalidate";
import type { KeysResponse } from "./src/gen/host/authority/v1/authority_pb.js";
import { WorkContextV1Schema, WorkScopeV1Schema, type WorkActorV1, type WorkContextV1, type WorkScopeV1 } from "./src/gen/host/authority/v1/work_context_pb.js";

/** Core's bounds: MaxTokenSize, DefaultSkew, MaxTTLCeiling. */
const MAX_TOKEN_BYTES = 32 * 1024, SKEW_SECONDS = 30, MAX_LIFETIME_SECONDS = 24 * 3600;
const validator = createValidator();
/** Core's conformance key: its private half is derivable from Core's public
 * source, so a key equal to it is refused whatever an authority publishes. */
const FIXTURE_PUBLIC = Buffer.from(createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), createHash("sha256").update("codefly work context conformance fixtures").digest()]),
  format: "der", type: "pkcs8",
}).export({ format: "jwk" }).x as string, "base64url");

export { Reason, Unauthenticated } from "./refusal.js";
import { Reason, Unauthenticated } from "./refusal.js";

/** The authority a module believes: its issuer and published keys, from Keys. */
export interface Trust {
  readonly issuer: string;
  /** Raw 32-byte Ed25519 public keys by key id. */
  readonly keys: ReadonlyMap<string, Uint8Array>;
  /** Unix milliseconds; Date.now when omitted. */
  readonly now?: () => number;
}

/** Trust from the authority interface's KeysResponse: Ed25519 keys only. */
export function trustFromKeys(response: KeysResponse, now?: () => number): Trust {
  const keys = new Map<string, Uint8Array>();
  for (const key of response.keys) {
    if (key.algorithm !== "Ed25519") continue;
    if (!key.keyId || keys.has(key.keyId) || key.publicKey.length !== 32) {
      throw new Unauthenticated(Reason.InvalidKey);
    }
    keys.set(key.keyId, Uint8Array.from(key.publicKey));
  }
  if (!response.issuer || keys.size === 0) throw new Unauthenticated(Reason.InvalidKey);
  return { issuer: response.issuer, keys, now };
}

export interface Scope {
  readonly resourceKind: string;
  readonly actions: readonly string[];
  readonly resourceIds: readonly string[];
  /** The principal whose resources the scope selects; "" selects no owner. */
  readonly resourceOwnerId: string;
}

export interface Claims {
  readonly audience: string;
  readonly scopes: readonly Scope[];
  /** The authenticated claims, whole. */
  readonly context: WorkContextV1;
  /** Empty resourceID asks for the entire kind. Actions and IDs are literal. */
  allows(kind: string, action: string, resourceID?: string): boolean;
  /** allows for a resource owned by ownerID: an owner-selected grant covers it
   * only when it names that owner; allows names none, so it never does. */
  allowsOwned(kind: string, action: string, resourceID: string, ownerID: string): boolean;
}

/** Server-side request headers; repeated values must not be discarded. */
export type StampHeaders = Readonly<Record<string, string | readonly string[]>> | Iterable<readonly [string, string]>;

/** The claims of the Work Context the hop forwarded to this module (audience), or
 * Unauthenticated naming why it must not be believed. */
export function authenticateClaims(headers: StampHeaders, audience: string, trust: Trust): Claims {
  if (!audience) throw new Unauthenticated(Reason.Configuration);
  return authenticateToken(boundToken(headers), audience, trust);
}

/** Authenticate bare bytes without claiming hop admission or live checks. */
export function authenticateToken(token: string, audience: string, trust: Trust): Claims {
  if (!audience) throw new Unauthenticated(Reason.Configuration);
  if (token.length > MAX_TOKEN_BYTES || token.split(".").length !== 2) {
    throw new Unauthenticated(Reason.Malformed);
  }
  const [payloadSegment, signatureSegment] = token.split(".");
  const payload = decodeSegment(payloadSegment), signature = signatureSegment === "" ? new Uint8Array() : decodeSegment(signatureSegment);
  let context: WorkContextV1;
  try {
    context = fromBinary(WorkContextV1Schema, payload, { readUnknownFields: false });
  } catch {
    throw new Unauthenticated(Reason.Malformed);
  }
  const checked = validator.validate(WorkContextV1Schema, context);
  if (checked.kind !== "valid") {
    throw new Unauthenticated(Reason.Malformed);
  }
  const canonical = toBinary(WorkContextV1Schema, context);
  if (canonical.length !== payload.length || canonical.some((byte, index) => byte !== payload[index])) {
    throw new Unauthenticated(Reason.Malformed);
  }
  const notBefore = Number(context.notBeforeUnix), expires = Number(context.expiresAtUnix);
  if (expires - notBefore > MAX_LIFETIME_SECONDS) throw new Unauthenticated(Reason.Lifetime);
  if (context.issuer !== trust.issuer) throw new Unauthenticated(Reason.Issuer);
  const raw = trust.keys.get(context.keyId);
  if (!raw) throw new Unauthenticated(Reason.UnknownKey);
  if (raw.length !== 32) throw new Unauthenticated(Reason.InvalidKey);
  if (Buffer.from(raw).equals(FIXTURE_PUBLIC)) {
    throw new Unauthenticated(Reason.FixtureKey);
  }
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" });
  if (signature.length !== 64 || !verify(null, payload, key, signature)) {
    throw new Unauthenticated(Reason.Signature);
  }
  if (context.audience !== audience) throw new Unauthenticated(Reason.Audience);
  const now = (trust.now ?? Date.now)() / 1000;
  if (now + SKEW_SECONDS < notBefore) throw new Unauthenticated(Reason.NotYetValid);
  if (!(now - SKEW_SECONDS < expires)) throw new Unauthenticated(Reason.Expired);
  checkStructure(context);
  const effective = context.actorChain.at(-1)?.grantedScopes ?? context.authorityScopes;
  const scopes = Object.freeze(effective.map(scope => Object.freeze({
    resourceKind: scope.resourceKind,
    actions: Object.freeze([...scope.actions]),
    resourceIds: Object.freeze([...scope.resourceIds]),
    resourceOwnerId: scope.resourceOwnerId,
  })));
  const allowsOwned = (kind: string, action: string, resourceID: string, ownerID: string): boolean => {
    if (!kind || !action) return false;
    return scopes.some(scope => scope.resourceKind === kind && scope.actions.includes(action) &&
      (scope.resourceOwnerId === "" || scope.resourceOwnerId === ownerID) &&
      (scope.resourceIds.length === 0 || (resourceID !== "" && scope.resourceIds.includes(resourceID))));
  };
  return Object.freeze({
    audience: context.audience,
    scopes,
    context,
    allows(kind: string, action: string, resourceID = ""): boolean {
      return allowsOwned(kind, action, resourceID, "");
    },
    allowsOwned,
  });
}

/** Core's ScopeContained: per action, a whole-kind row covers it, or the child's
 * ids all lie within the rows of that kind holding the action. A row naming an
 * owner covers only a child naming the same owner. */
export function scopeContained(child: WorkScopeV1, parents: readonly WorkScopeV1[]): boolean {
  if (!parents.some(p => p.resourceKind === child.resourceKind)) return false;
  for (const action of child.actions) {
    const rows = parents.filter(p => p.resourceKind === child.resourceKind && p.actions.includes(action) &&
      (p.resourceOwnerId === "" || p.resourceOwnerId === child.resourceOwnerId));
    if (rows.some(p => p.resourceIds.length === 0)) continue;
    const ids = new Set(rows.flatMap(p => p.resourceIds));
    if (child.resourceIds.length === 0 || child.resourceIds.some(id => !ids.has(id))) return false;
  }
  return true;
}

function identityKey(context: WorkContextV1, hop?: WorkActorV1): string {
  return JSON.stringify(hop
    ? [hop.principalId, hop.principalKind, hop.agentId ?? "", hop.organizationId || context.organizationId || ""]
    : [context.ownerPrincipalId, context.ownerPrincipalKind ?? "", context.ownerAgentId ?? "", context.organizationId ?? ""]);
}

/** Core's checkStructure: every hop attenuates the one before it, and a grant
 * hop elevates exactly the hop it names, for one action on one resource. */
function checkStructure(context: WorkContextV1): void {
  const grant = context.grantHop, chain = context.actorChain;
  let effective = context.authorityScopes;
  chain.forEach((hop, index) => {
    const elevated = grant !== undefined && index === chain.length - 1;
    if (!elevated && !hop.grantedScopes.every(scope => scopeContained(scope, effective))) {
      throw new Unauthenticated(Reason.Attenuation);
    }
    effective = hop.grantedScopes;
  });
  if (grant === undefined) return;
  const name = grant.grantId;
  if (chain.length === 0) throw new Unauthenticated(Reason.Grant);
  if (context.parentSessionId === undefined) throw new Unauthenticated(Reason.Grant);
  if (context.replayPolicy !== "single-use") throw new Unauthenticated(Reason.Grant);
  const scope = grant.grantedScope;
  if (!scope || scope.actions.length !== 1 || scope.resourceIds.length !== 1) {
    throw new Unauthenticated(Reason.Grant);
  }
  const last = chain[chain.length - 1];
  if (last.grantedScopes.length !== 1 || !equals(WorkScopeV1Schema, last.grantedScopes[0], scope)) {
    throw new Unauthenticated(Reason.Grant);
  }
  if (last.delegationId !== name) throw new Unauthenticated(Reason.Grant);
  const actor = chain.length > 1 ? identityKey(context, chain[chain.length - 2]) : identityKey(context);
  if (identityKey(context, last) !== actor) throw new Unauthenticated(Reason.Grant);
}

/** Extract one digest-bound token. This is not hop admission authentication:
 * checkCall and a shared ReplayStore establish that, normally via Verifier. */
export function boundToken(headers: StampHeaders): string {
  if (headers === null || typeof headers !== "object") {
    throw new Unauthenticated(Reason.Configuration);
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
  if (!token || values.get("x-codefly-hop-context")?.length !== 1) throw new Unauthenticated(Reason.StampToken);
  if (!equal(createHash("sha256").update(token).digest("hex"), one("x-codefly-hop-context"))) {
    throw new Unauthenticated(Reason.StampDigest);
  }
  return token;
}

function decodeSegment(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new Unauthenticated(Reason.Malformed);
  const decoded = Buffer.from(segment, "base64url");
  if (decoded.toString("base64url") !== segment) throw new Unauthenticated(Reason.Malformed);
  return new Uint8Array(decoded);
}

/** Who a call is for, read from the authenticated Work Context. */
export interface Identity {
  readonly owner: string;
  readonly ownerKind: string;
  readonly tenant: string;
  readonly actors: readonly string[];
  /** Kind-wide effective scopes, each "<kind>:<action>"; claims.allows answers resource-exact questions. */
  readonly scopes: readonly string[];
  readonly binding: string;
  readonly task: string;
  readonly expires: number;
  /** The authenticated Work Context, as forwarded. */
  readonly context: string;
  /** The refusal the hop allowed in warning mode; diagnostic, grants nothing. */
  readonly advisory: string;
  readonly claims: Claims;
}

function flatten(scopes: readonly WorkScopeV1[]): string[] {
  const out: string[] = [];
  for (const scope of scopes) {
    if (scope.resourceIds.length > 0 || scope.resourceOwnerId !== "") continue;
    for (const action of scope.actions) if (!out.includes(`${scope.resourceKind}:${action}`)) out.push(`${scope.resourceKind}:${action}`);
  }
  return out;
}

/** The Go library's IdentityOf: the owner's authority narrowed by every actor's
 * grant (an actor granted nothing narrows to nothing); resource-limited scopes
 * are left out rather than widened. */
export function identityOf(context: WorkContextV1): Omit<Identity, "context" | "advisory" | "claims"> {
  let scopes = flatten(context.authorityScopes);
  for (const actor of context.actorChain) {
    const held = flatten(actor.grantedScopes);
    scopes = scopes.filter(scope => held.includes(scope));
  }
  return {
    owner: context.ownerPrincipalId, ownerKind: context.ownerPrincipalKind ?? "", tenant: context.tenantId,
    actors: context.actorChain.map(actor => actor.principalId), scopes,
    binding: context.operationBinding?.bindingId ?? "", task: context.taskId, expires: Number(context.expiresAtUnix),
  };
}

/** The authority interface's Keys, as its generated Connect client serves it. */
export interface KeySource {
  keys(request: object, options?: { timeoutMs?: number; signal?: AbortSignal }): Promise<KeysResponse>;
}

/** The Go verifier's key policy: re-read on an unknown key at most every 10 s and
 * when older than 5 min, on a read of its own bounded by 5 s; keys that cannot be
 * re-read are trusted no longer than 15 min. */
const KEY_RETRY_MS = 10_000, KEY_MAX_AGE_MS = 300_000, KEY_STALE_MS = 900_000, KEY_TIMEOUT_MS = 5_000;

/** The one module-side entry point: authenticates every call the hop forwards.
 * Build it once at startup with the generated client of the authority interface
 * the module depends on; the keys are read through its Keys, never typed in.
 * Construction never fails on an authority that is not serving yet: calls are
 * refused, with the reason, until its keys are read. */
export class Verifier {
  private trust?: Trust;
  private fetched = 0;
  private tried = Number.NEGATIVE_INFINITY;
  private inflight?: Promise<void>;
  /** The last key-read failure, for the module's own logs; never sent to a caller. */
  keysError?: unknown;

  constructor(private readonly source: KeySource, private readonly audience: string,
              private readonly publicKey?: string, private readonly replay?: ReplayStore,
              private readonly now: () => number = Date.now, private readonly timeoutMs: number = KEY_TIMEOUT_MS) {
    if (!source || !audience) throw new Unauthenticated(Reason.Configuration);
    // Admission needs both the delivered hop public key and a store every
    // replica shares; one without the other admits nothing.
    if ((publicKey !== undefined || replay !== undefined) && (!replay || !/^[0-9a-f]{64}$/.test(publicKey ?? ""))) {
      throw new Unauthenticated(Reason.Configuration);
    }
    void this.refresh();
  }

  /** Whether trusted keys are held: true from the first successful read and
   * through failed re-reads inside the 15-minute window; false before any read
   * succeeded or once the keys are stale. Readiness uses this, never keysError.
   * It also starts the read a call would (keys missing or older than 5 min, at
   * most every 10 s, never waiting), so an unready replica, which gets no calls,
   * recovers, and an idle one never goes stale. */
  ready(): boolean {
    const now = this.now();
    if ((!this.trust || now - this.fetched > KEY_MAX_AGE_MS) && !this.inflight && now - this.tried >= KEY_RETRY_MS) void this.refresh();
    return this.trust !== undefined && now - this.fetched <= KEY_STALE_MS;
  }

  /** Who the call is for, or Unauthenticated naming why it is refused. */
  async verify(headers: StampHeaders, method: string): Promise<Identity> {
    const pairs = [...(Symbol.iterator in Object(headers) ? headers as Iterable<readonly [string, string]> : Object.entries(headers))]
      .flatMap(([key, value]) => (typeof value === "string" ? [value] : [...value]).map(v => [key.toLowerCase(), v] as const));
    if (this.publicKey === undefined || this.replay === undefined) {
      // A token-only verifier holds neither the hop's public key nor a replay
      // store, so it can establish no admission.
      throw new Unauthenticated(Reason.Configuration);
    }
    // The admission first: nothing signed for another procedure, another
    // audience or another token reaches the key read.
    const call = checkCall(pairs, this.publicKey, method, this.audience, this.now());
    const token = boundToken(pairs);
    const id = await this.verifyToken(token);
    const stamped: Record<string, string> = {
      "x-codefly-hop-owner": id.owner, "x-codefly-hop-owner-kind": id.ownerKind, "x-codefly-hop-tenant": id.tenant,
      "x-codefly-hop-actors": id.actors.join(","), "x-codefly-hop-scopes": id.scopes.join(","),
      "x-codefly-hop-binding": id.binding, "x-codefly-hop-task": id.task, "x-codefly-hop-expires": id.expires > 0 ? String(id.expires) : "",
    };
    for (const [key, want] of Object.entries(stamped)) {
      const got = pairs.filter(([name]) => name === key).map(([, value]) => value);
      if (got.length > 1 || (got[0] ?? "") !== want) {
        throw new Unauthenticated(Reason.StampIdentity);
      }
    }
    if (call.expires <= Math.floor(this.now() / 1000)) throw new Unauthenticated(Reason.StampWindow);
    try { await this.replay.consume(call.nonce, call.expires); }
    catch (error) { throw new Unauthenticated(error instanceof Replayed ? Reason.StampReplayed : Reason.StampStore); }
    if (call.expires <= Math.floor(this.now() / 1000)) throw new Unauthenticated(Reason.StampWindow);
    // An admission carrying an advisory refusal is refused by checkCall, so an
    // admitted call never has one: diagnostic identity is never authority.
    return Object.freeze({ ...id, advisory: "" });
  }

  /** Authenticate a bare token with the stamped path's fail-closed key cache.
   * It establishes no admission: no method binding, no nonce consumption. */
  async verifyToken(token: string): Promise<Identity> {
    const claims = authenticateToken(token, this.audience, await this.trustFor(keyIdOf(token)));
    return Object.freeze({ ...identityOf(claims.context), context: token, claims, advisory: "" });
  }

  private async trustFor(keyId: string): Promise<Trust> {
    const now = this.now();
    const held = this.trust?.keys.has(keyId) ?? false;
    if ((!held || now - this.fetched > KEY_MAX_AGE_MS) && now - this.tried >= KEY_RETRY_MS) void this.refresh();
    // A key not held, or held keys past the stale window, cannot judge this call:
    // it waits for the read, which ends within the verifier's own timeout, so an
    // idle replica's first call is judged on fresh keys, not refused while they arrive.
    if ((!held || now - this.fetched > KEY_STALE_MS) && this.inflight) await this.inflight;
    if (!this.trust || this.now() - this.fetched > KEY_STALE_MS) {
      if (this.keysError instanceof Unauthenticated && this.keysError.code === Reason.InvalidKey) throw new Unauthenticated(Reason.InvalidKey);
      throw new Unauthenticated(Reason.KeysUnavailable);
    }
    return { ...this.trust, now: this.now };
  }

  /** One read at a time, on its own timeout: no caller's signal or failure delays
   * the next. The read ends at the timeout whether or not the source honours it,
   * so no waiting call and no later read is held by a source that never answers. */
  private refresh(): Promise<void> {
    if (this.inflight) return this.inflight;
    this.tried = this.now();
    const signal = AbortSignal.timeout(this.timeoutMs);
    const deadline = new Promise<never>((_, reject) => signal.addEventListener("abort", () => reject(signal.reason), { once: true }));
    this.inflight = Promise.race([this.source.keys({}, { timeoutMs: this.timeoutMs, signal }), deadline])
      .then(response => { this.trust = trustFromKeys(response); this.fetched = this.now(); this.keysError = undefined; })
      .catch(error => { this.keysError = error; })
      .finally(() => { this.inflight = undefined; });
    return this.inflight;
  }
}

function keyIdOf(token: string): string {
  if (token.length > MAX_TOKEN_BYTES) return "";
  try {
    return fromBinary(WorkContextV1Schema, Buffer.from(token.split(".")[0], "base64url")).keyId;
  } catch {
    return "";
  }
}
