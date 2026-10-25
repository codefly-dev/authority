/** Non-verifying projection of an already hop-bound Work Context. */
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

/**
 * Read the context bound by a trusted integration; this library supplies no
 * TypeScript hop reader. A projection authenticates nothing and checks neither
 * liveness nor replay. In warn mode even bound claims may have been refused.
 */
export function readClaims(token: string): Claims {
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
