"""Authenticate the Work Context the hop forwarded to a module, then project it.

``authenticate`` is the Go library's ``workcontext.Authenticate``, check for
check: the stamp binds exactly one token to this run's hop proof by its digest,
and the token itself must carry a valid Ed25519 signature under the authority's
published key, name the pinned issuer, be addressed to this module and be inside
its window, judged in Core's order and by Core's rules: the decode path (size,
schema, unknown fields, canonical encoding, lifetime), the issuer pin, the key
(never Core's public conformance key), the signature, the audience, the window,
and the chain's attenuation and grant shape. The schema rules are the contract's
own ``buf.validate`` declarations, run by protovalidate against the published
contract descriptor, not restated here. ``testdata/vectors.json``, written by the
Go test, holds every rule to Go's verdict.

The SaaS Python SDK's verifier was not reused because it refuses tokens Core
accepts (several scope rows of one kind, Core's own grant fixture).
Nothing here asks the authority or consumes a nonce: liveness is the
authority's Check the hop made, which the digest binds to this call.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from importlib import resources

import protovalidate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError

from ._gen.host.authority.v1.work_context_pb2 import WorkContextV1

WORK_CONTEXT_KEY = "x-codefly-work-context"
PROOF_KEY = "x-codefly-hop-proof"
CONTEXT_KEY = "x-codefly-hop-context"
ALGORITHM = "Ed25519"
# Core's bounds: MaxTokenSize, DefaultSkew and MaxTTLCeiling.
MAX_TOKEN_BYTES = 32 * 1024
SKEW = timedelta(seconds=30)
MAX_LIFETIME = timedelta(hours=24)
REPLAY_SINGLE_USE = "single-use"
# Core's conformance key: its private half is derivable from Core's public source,
# so a key equal to it is refused whatever an authority publishes (Core's resolveKey).
_FIXTURE_PUBLIC = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"codefly work context conformance fixtures").digest()
).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _contract_class():
    """WorkContextV1 as the published contract declares it, buf.validate rules
    included (the generated Python module was emitted without them)."""
    files = descriptor_pb2.FileDescriptorSet()
    files.ParseFromString(resources.files("authority_client").joinpath("contract.binpb").read_bytes())
    pool = descriptor_pool.DescriptorPool()
    for file in files.file:
        pool.Add(file)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("host.authority.v1.WorkContextV1"))


_CONTRACT = _contract_class()


class Unauthenticated(ValueError):
    """The forwarded Work Context must not be believed; the message names why."""


class Trust:
    """The authority a module believes: the issuer every capability must name and
    its published verification keys by key id, as the authority interface's Keys
    answers them. Build it with ``from_keys``; never type a key in."""

    def __init__(self, issuer: str, keys: Mapping[str, bytes], *, now: Callable[[], datetime] | None = None) -> None:
        if not issuer:
            raise Unauthenticated("the authority names no issuer")
        if not keys:
            raise Unauthenticated("the authority publishes no verification key")
        self.issuer = issuer
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.raw = {key_id: bytes(raw) for key_id, raw in keys.items()}
        try:
            self.keys = {key_id: Ed25519PublicKey.from_public_bytes(raw) for key_id, raw in self.raw.items()}
        except ValueError as error:
            raise Unauthenticated(f"the authority's keys are unusable: {error}") from error

    @classmethod
    def from_keys(cls, response, *, now: Callable[[], datetime] | None = None) -> "Trust":
        """Trust built from the authority interface's KeysResponse. Only Ed25519
        keys are kept; an empty or repeated key id is refused."""
        keys: dict[str, bytes] = {}
        for key in response.keys:
            if key.algorithm != ALGORITHM:
                continue
            if not key.key_id or key.key_id in keys:
                raise Unauthenticated("the authority publishes an unnamed or repeated key id")
            keys[key.key_id] = bytes(key.public_key)
        return cls(response.issuer, keys, now=now)


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
    # The authenticated claims, whole.
    context: WorkContextV1 | None = field(default=None, compare=False, repr=False)

    def allows(self, kind: str, action: str, resource_id: str = "") -> bool:
        """One exact action on one resource; empty ID asks for the whole kind.

        Each grant is considered independently. Actions are literal, as in Core's
        scope containment; no admin implication or wildcard expansion happens
        here. A kind-wide grant includes any named resource.
        """
        if not kind or not action:
            return False
        return any(
            scope.resource_kind == kind
            and action in scope.actions
            and (not scope.resource_ids or bool(resource_id) and resource_id in scope.resource_ids)
            for scope in self.scopes
        )


def authenticate(
    headers: Mapping[str, str] | Iterable[tuple[str, str]], proof: str, audience: str, trust: Trust
) -> Claims:
    """The claims of the Work Context the hop forwarded with headers to this module
    (audience), or ``Unauthenticated`` naming why it must not be believed."""
    if not audience:
        raise Unauthenticated("no audience: a module authenticates a context for itself")
    token = bound_token(headers, proof)
    if len(token) > MAX_TOKEN_BYTES or not token.isascii() or token.count(".") != 1:
        raise Unauthenticated("expected a bounded <payload>.<signature> context")
    payload_segment, signature_segment = token.split(".")
    payload, signature = _canonical(payload_segment), _canonical(signature_segment)
    context = WorkContextV1()
    try:
        context.ParseFromString(payload)
    except DecodeError as error:
        raise Unauthenticated("payload is not a WorkContextV1") from error
    try:
        protovalidate.validate(_parsed(_CONTRACT, payload))
    except protovalidate.ValidationError as error:
        raise Unauthenticated(f"invalid claims: {error}") from error
    context.DiscardUnknownFields()
    if context.SerializeToString(deterministic=True) != payload:
        raise Unauthenticated("payload is noncanonical or carries a field this reader does not know")
    if context.expires_at_unix - context.not_before_unix > MAX_LIFETIME.total_seconds():
        raise Unauthenticated(f"the capability's lifetime exceeds {MAX_LIFETIME}")
    if context.issuer != trust.issuer:
        raise Unauthenticated(f"issued by {context.issuer!r}, not {trust.issuer!r}")
    key = trust.keys.get(context.key_id)
    if key is None:
        raise Unauthenticated(f"no verification key {context.key_id!r}; the authority does not publish it")
    if trust.raw[context.key_id] == _FIXTURE_PUBLIC:
        raise Unauthenticated(f"key {context.key_id!r} is the conformance fixture key, which anyone can derive from Core's source")
    try:
        key.verify(signature, payload)
    except InvalidSignature:
        raise Unauthenticated("signature does not verify under the authority's published key") from None
    if context.audience != audience:
        raise Unauthenticated(f"minted for audience {context.audience!r}, presented to {audience!r}")
    now = trust.now().timestamp()
    if now + SKEW.total_seconds() < context.not_before_unix:
        raise Unauthenticated("not valid before its not-before instant")
    if not now - SKEW.total_seconds() < context.expires_at_unix:
        raise Unauthenticated("expired")
    _check_structure(context)
    scopes = context.actor_chain[-1].granted_scopes if context.actor_chain else context.authority_scopes
    return Claims(
        audience=context.audience,
        scopes=tuple(Scope(s.resource_kind, tuple(s.actions), tuple(s.resource_ids)) for s in scopes),
        context=context,
    )


def _parsed(cls, payload: bytes):
    message = cls()
    message.ParseFromString(payload)
    return message


def scope_contained(child, parents) -> bool:
    """Core's ScopeContained: per action, a whole-kind row covers it, or the
    child's ids all lie within the rows of that kind holding the action."""
    if not any(parent.resource_kind == child.resource_kind for parent in parents):
        return False
    for action in child.actions:
        rows = [p for p in parents if p.resource_kind == child.resource_kind and action in p.actions]
        if any(not p.resource_ids for p in rows):
            continue
        ids = {i for p in rows for i in p.resource_ids}
        if not child.resource_ids or any(i not in ids for i in child.resource_ids):
            return False
    return True


def _identity(context, hop=None) -> tuple:
    if hop is None:
        return (context.owner_principal_id, context.owner_principal_kind, context.owner_agent_id, context.organization_id)
    return (hop.principal_id, hop.principal_kind, hop.agent_id, hop.organization_id or context.organization_id)


def _check_structure(context) -> None:
    """Core's checkStructure: every hop attenuates the one before it, and a grant
    hop elevates exactly the hop it names, for one action on one resource."""
    grant = context.grant_hop if context.HasField("grant_hop") else None
    chain = context.actor_chain
    effective = context.authority_scopes
    for index, hop in enumerate(chain):
        elevated = grant is not None and index == len(chain) - 1
        if not elevated and not all(scope_contained(s, effective) for s in hop.granted_scopes):
            raise Unauthenticated(f"actor hop {index} ({hop.principal_id}) widens authority beyond the hop before it")
        effective = hop.granted_scopes
    if grant is None:
        return
    name = grant.grant_id
    if not chain:
        raise Unauthenticated(f"grant {name!r} has no actor hop to elevate")
    if not context.HasField("parent_session_id"):
        raise Unauthenticated(f"grant {name!r} is not a child session")
    if context.replay_policy != REPLAY_SINGLE_USE:
        raise Unauthenticated(f"grant {name!r} is replayable; a grant authorizes one call")
    scope = grant.granted_scope
    if len(scope.actions) != 1 or len(scope.resource_ids) != 1:
        raise Unauthenticated(f"grant {name!r} must name exactly one action on one resource")
    last = chain[-1]
    if len(last.granted_scopes) != 1 or last.granted_scopes[0] != scope:
        raise Unauthenticated(f"grant {name!r} elevates a hop holding something other than the granted scope")
    if last.delegation_id != name:
        raise Unauthenticated(f"grant {name!r} elevates a hop delegated by {last.delegation_id!r}")
    actor = _identity(context, chain[-2]) if len(chain) > 1 else _identity(context)
    if _identity(context, last) != actor:
        raise Unauthenticated(f"grant {name!r} hands authority to another principal rather than elevating it")


def bound_token(headers: Mapping[str, str] | Iterable[tuple[str, str]], proof: str) -> str:
    """The one token the stamp's digest binds under this run's proof. Bound, not
    authenticated: whoever holds the proof can write both."""
    values = collect(headers)
    proofs, tokens, digests = values.get(PROOF_KEY, []), values.get(WORK_CONTEXT_KEY, []), values.get(CONTEXT_KEY, [])
    if not proof or len(proofs) != 1 or not hmac.compare_digest(proofs[0].encode(), proof.encode()):
        raise Unauthenticated("the call did not come through the hop: it carries no stamp with this run's proof")
    if len(tokens) != 1 or not tokens[0] or len(digests) != 1:
        raise Unauthenticated("the stamp binds no single Work Context")
    digest = hashlib.sha256(tokens[0].encode(errors="surrogatepass")).hexdigest()
    if not hmac.compare_digest(digest.encode(), digests[0].encode()):
        raise Unauthenticated("the Work Context is not the one the hop's stamp binds")
    return tokens[0]


def collect(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    """Headers by lower-cased name, repeats kept: a single-value mapping cannot
    show a second token a caller appended."""
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    values: dict[str, list[str]] = {}
    for key, value in pairs:
        values.setdefault(key.lower(), []).append(value)
    return values


def _canonical(segment: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except ValueError as error:
        raise Unauthenticated("context segment is not base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise Unauthenticated("context segment is not canonical base64url")
    return decoded
