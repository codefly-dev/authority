/** Non-verifying projection of an already hop-bound Work Context. */
import { createHash, timingSafeEqual } from "node:crypto";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { WorkContextV1Schema } from "./src/gen/host/authority/v1/work_context_pb.js";

export class UnreadableContext extends Error {
  override name = "UnreadableContext";
}

export interface Scope {
  readonly resourceKind: string;
  readonly actions: readonly string[];
  readonly resourceIds: readonly string[];
}

export interface Claims {
  readonly audience: string;
  readonly scopes: readonly Scope[];
  /** Empty resourceID asks for the entire kind. Actions and IDs are literal. */
  allows(kind: string, action: string, resourceID?: string): boolean;
}

/** Server-side request headers; repeated values must not be discarded. */
export type StampHeaders = Readonly<Record<string, string | readonly string[]>> | Iterable<readonly [string, string]>;

/** Verify the run proof and token digest before projecting. This is not another
 * signature, liveness or replay check. In warn mode bound claims may be refused. */
export function readClaims(headers: StampHeaders, proof: string): Claims {
  if (headers === null || typeof headers !== "object" || typeof proof !== "string") {
    throw new UnreadableContext("context requires request headers and a run proof");
  }
  const values = new Map<string, string[]>();
  const pairs = Symbol.iterator in Object(headers) ? headers as Iterable<readonly [string,string]> : Object.entries(headers);
  for (const [key,value] of pairs) {
    const name=key.toLowerCase();
    values.set(name,[...(values.get(name) ?? []),...(typeof value === "string" ? [value] : value)]);
  }
  const one=(key:string):string => { const v=values.get(key); return v?.length === 1 ? v[0] : ""; };
  const equal=(a:string,b:string):boolean => {
    const left=new TextEncoder().encode(a),right=new TextEncoder().encode(b);
    return left.length === right.length && timingSafeEqual(left,right);
  };
  const token=one("x-codefly-work-context");
  if (!proof || !equal(proof,one("x-codefly-hop-proof")) || !token || token.length > 32*1024 ||
      !equal(createHash("sha256").update(token).digest("hex"),one("x-codefly-hop-context"))) {
    throw new UnreadableContext("context requires this run's hop proof and matching stamp");
  }
  if (!token || token.length > 32 * 1024 || token.split(".").length !== 2) {
    throw new UnreadableContext("expected a bounded payload.signature context");
  }
  const [payloadSegment, signatureSegment] = token.split(".");
  const payload = decodeSegment(payloadSegment);
  if (decodeSegment(signatureSegment).length !== 64) {
    throw new UnreadableContext("expected a 64-byte signature");
  }
  let context;
  try {
    context = fromBinary(WorkContextV1Schema, payload, { readUnknownFields: false });
  } catch {
    throw new UnreadableContext("payload is not a WorkContextV1");
  }
  const canonical = toBinary(WorkContextV1Schema, context);
  if (!context.audience || canonical.length !== payload.length ||
      canonical.some((byte, index) => byte !== payload[index])) {
    throw new UnreadableContext("payload is noncanonical, has unknown fields or names no audience");
  }
  const effective = context.actorChain.at(-1)?.grantedScopes ?? context.authorityScopes;
  const scopes = Object.freeze(effective.map(scope => Object.freeze({
    resourceKind: scope.resourceKind,
    actions: Object.freeze([...scope.actions]),
    resourceIds: Object.freeze([...scope.resourceIds]),
  })));
  return Object.freeze({
    audience: context.audience,
    scopes,
    allows(kind: string, action: string, resourceID = ""): boolean {
      if (!kind || !action) return false;
      return scopes.some(scope => scope.resourceKind === kind && scope.actions.includes(action) &&
        (scope.resourceIds.length === 0 || (resourceID !== "" && scope.resourceIds.includes(resourceID))));
    },
  });
}

function decodeSegment(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new UnreadableContext("context segment is not base64url");
  }
  let decoded: string;
  try {
    decoded = atob(segment.replace(/-/g, "+").replace(/_/g, "/"));
  } catch {
    throw new UnreadableContext("context segment is not base64url");
  }
  if (btoa(decoded).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") !== segment) {
    throw new UnreadableContext("context segment is not canonical base64url");
  }
  return Uint8Array.from(decoded, character => character.charCodeAt(0));
}
