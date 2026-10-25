"""Non-verifying projection of the Work Context already bound by a hop stamp.

Pass the incoming headers and this run's delivered hop proof to ``read_claims``.
This is a reader, not Core's structural validator or a verifier: it checks neither
signature, liveness, revocation nor delegation. In warning mode the hop may have
forwarded a refused context; its advisory remains diagnostic, never a grant.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from collections.abc import Iterable, Mapping
from codefly_hop import read, NoStamp

from google.protobuf.message import DecodeError

from ._gen.host.authority.v1.work_context_pb2 import WorkContextV1

# The existing Core and Python SDK envelope bound, before decoding allocates.
MAX_TOKEN_BYTES = 32 * 1024


class UnreadableContext(ValueError):
    """The forwarded token cannot be projected through the published wire type."""


@dataclass(frozen=True)
class Scope:
    resource_kind: str
    actions: tuple[str, ...]
    resource_ids: tuple[str, ...]


@dataclass(frozen=True)
class Claims:
    audience: str
    # Core's effective scopes: the last actor's grants, or the owner's if no actor.
    scopes: tuple[Scope, ...]

    def allows(self, kind: str, action: str, resource_id: str = "") -> bool:
        """One exact action on one resource; empty ID asks for the whole kind.

        Each grant is considered independently. Actions are literal, as in Core's
        scope containment and the Python SDK; no admin implication or wildcard
        expansion happens here. A kind-wide grant includes any named resource.
        """
        if not kind or not action:
            return False
        return any(
            scope.resource_kind == kind
            and action in scope.actions
            and (not scope.resource_ids or bool(resource_id) and resource_id in scope.resource_ids)
            for scope in self.scopes
        )


def read_claims(headers: Mapping[str, str] | Iterable[tuple[str, str]], proof: str) -> Claims:
    """Read an already hop-bound context without another verification/replay call.

    Uses the published generated protobuf type. The canonical-envelope/payload
    checks follow the existing Python SDK's algorithm, maintained here during
    migration rather than imported from its private helpers. Unknown fields are
    refused rather than silently losing a restriction. Consumers still check audience and resolve the
    exact domain resource; this projection alone is never proof of authority.
    """
    try:
        token = read(headers, proof).context
    except (NoStamp, TypeError, ValueError) as error:
        raise UnreadableContext("context requires this run's hop proof and matching stamp") from error
    if not token:
        raise UnreadableContext("context requires a token bound by the hop stamp")
    if not token.isascii() or len(token) > MAX_TOKEN_BYTES or token.count(".") != 1:
        raise UnreadableContext("expected a bounded <payload>.<signature> context")
    payload_segment, signature_segment = token.split(".")
    payload = _decode_segment(payload_segment)
    if len(_decode_segment(signature_segment)) != 64:
        raise UnreadableContext("expected a 64-byte signature")
    context = WorkContextV1()
    try:
        context.ParseFromString(payload)
    except DecodeError as error:
        raise UnreadableContext("payload is not a WorkContextV1") from error
    context.DiscardUnknownFields()
    if context.SerializeToString(deterministic=True) != payload or not context.audience:
        raise UnreadableContext("payload is noncanonical, has unknown fields or names no audience")
    scopes = context.actor_chain[-1].granted_scopes if context.actor_chain else context.authority_scopes
    return Claims(
        audience=context.audience,
        scopes=tuple(Scope(s.resource_kind, tuple(s.actions), tuple(s.resource_ids)) for s in scopes),
    )


def _decode_segment(segment: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except ValueError as error:
        raise UnreadableContext("context segment is not base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise UnreadableContext("context segment is not canonical base64url")
    return decoded
