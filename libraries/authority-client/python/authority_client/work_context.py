"""Authenticate the Work Context the hop forwarded to a module, then project it.

``authenticate_token`` is the Go library's ``workcontext.AuthenticateToken``, check for
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


from enum import Enum

class Reason(str, Enum):
    """Stable caller-safe refusal categories."""
    CONFIGURATION = "configuration"
    STAMPPROOF = "stamp_proof"
    STAMPTOKEN = "stamp_token"
    STAMPDIGEST = "stamp_digest"
    STAMPIDENTITY = "stamp_identity"
    STAMPMETHOD = "stamp_method"
    STAMPAUDIENCE = "stamp_audience"
    STAMPWINDOW = "stamp_window"
    STAMPISSUED = "stamp_issued"
    STAMPADVISORY = "stamp_advisory"
    STAMPREPLAYED = "stamp_replayed"
    STAMPSTORE = "stamp_store"
    KEYSUNAVAILABLE = "keys_unavailable"
    CANCELLED = "cancelled"
    MALFORMED = "malformed"
    LIFETIME = "lifetime"
    ISSUER = "issuer"
    UNKNOWNKEY = "unknown_key"
    INVALIDKEY = "invalid_key"
    FIXTUREKEY = "fixture_key"
    SIGNATURE = "signature"
    AUDIENCE = "audience"
    NOTYETVALID = "not_yet_valid"
    EXPIRED = "expired"
    ATTENUATION = "attenuation"
    GRANT = "grant"


_REASON_TEXT = {
    Reason.CONFIGURATION: 'the verifier configuration is incomplete',
    Reason.STAMPPROOF: 'the call carries no hop admission signed for it',
    Reason.STAMPTOKEN: 'the stamp binds no single Work Context',
    Reason.STAMPDIGEST: 'the Work Context does not match the hop stamp',
    Reason.STAMPIDENTITY: 'the stamp does not match the authenticated Work Context',
    Reason.STAMPMETHOD: 'the hop admission was signed for another procedure',
    Reason.STAMPAUDIENCE: 'the hop admission was signed for another module',
    Reason.STAMPWINDOW: 'the hop admission is expired or outside its validity window',
    Reason.STAMPISSUED: 'the hop admission is issued further ahead than the clock allowance',
    Reason.STAMPADVISORY: 'an advisory policy refusal cannot admit a call',
    Reason.STAMPREPLAYED: 'the hop admission has already been used',
    Reason.STAMPSTORE: 'the hop admission store is unavailable',
    Reason.KEYSUNAVAILABLE: "the authority's published keys are unavailable",
    Reason.CANCELLED: "the call ended while the authority's keys were being read",
    Reason.MALFORMED: 'the Work Context encoding or claims are invalid',
    Reason.LIFETIME: 'the capability lifetime exceeds the allowed bound',
    Reason.ISSUER: 'the Work Context was issued by an untrusted issuer',
    Reason.UNKNOWNKEY: 'no verification key is published for this Work Context',
    Reason.INVALIDKEY: "the authority's verification key is malformed",
    Reason.FIXTUREKEY: 'the conformance fixture key is refused',
    Reason.SIGNATURE: 'the signature does not verify under the published key',
    Reason.AUDIENCE: 'the Work Context was minted for another audience',
    Reason.NOTYETVALID: 'the Work Context is not valid before its not-before instant',
    Reason.EXPIRED: 'the Work Context has expired',
    Reason.ATTENUATION: 'the actor chain widens authority',
    Reason.GRANT: 'the grant structure is invalid',
}

class Unauthenticated(ValueError):
    """Contains only a code and fixed safe text, never diagnostic causes."""
    def __init__(self, reason: Reason):
        self.reason = reason
        self.code = reason.value
        self.text = _REASON_TEXT[reason]
        super().__init__(f"{self.code}: {self.text}")



class Trust:
    """The authority a module believes: the issuer every capability must name and
    its published verification keys by key id, as the authority interface's Keys
    answers them. Build it with ``from_keys``; never type a key in."""

    def __init__(self, issuer: str, keys: Mapping[str, bytes], *, now: Callable[[], datetime] | None = None) -> None:
        if not issuer:
            raise Unauthenticated(Reason.INVALIDKEY)
        if not keys:
            raise Unauthenticated(Reason.INVALIDKEY)
        self.issuer = issuer
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.raw = {key_id: bytes(raw) for key_id, raw in keys.items()}
        try:
            self.keys = {key_id: Ed25519PublicKey.from_public_bytes(raw) for key_id, raw in self.raw.items()}
        except ValueError as error:
            raise Unauthenticated(Reason.INVALIDKEY) from None

    @classmethod
    def from_keys(cls, response, *, now: Callable[[], datetime] | None = None) -> "Trust":
        """Trust built from the authority interface's KeysResponse. Only Ed25519
        keys are kept; an empty or repeated key id is refused."""
        keys: dict[str, bytes] = {}
        for key in response.keys:
            if key.algorithm != ALGORITHM:
                continue
            if not key.key_id or key.key_id in keys:
                raise Unauthenticated(Reason.INVALIDKEY)
            keys[key.key_id] = bytes(key.public_key)
        return cls(response.issuer, keys, now=now)


@dataclass(frozen=True)
class Scope:
    resource_kind: str
    actions: tuple[str, ...]
    resource_ids: tuple[str, ...]
    # The principal whose resources the scope selects; "" selects no owner.
    resource_owner_id: str = ""


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
        return self.allows_owned(kind, action, resource_id, "")

    def allows_owned(self, kind: str, action: str, resource_id: str, owner_id: str) -> bool:
        """``allows`` for a resource owned by owner_id, as the module's own record
        names it: an owner-selected grant covers it only when it names that
        owner (and, with ids, the id too); a grant naming no owner covers it
        whatever its owner. ``allows`` names no owner, so an owner-selected
        grant never satisfies it. An empty ID with an owner asks for every
        resource that owner holds."""
        if not kind or not action:
            return False
        return any(
            scope.resource_kind == kind
            and action in scope.actions
            and (not scope.resource_owner_id or scope.resource_owner_id == owner_id)
            and (not scope.resource_ids or bool(resource_id) and resource_id in scope.resource_ids)
            for scope in self.scopes
        )


def authenticate_token(token: str, audience: str, trust: Trust) -> Claims:
    """The claims of one Work Context, for this module (``audience``), or
    ``Unauthenticated`` naming why they must not be believed.

    This is the one identity-only reader here, and identity is all it
    establishes. It proves no hop admission: it does not check that a call was
    admitted for the procedure it arrived on, consumes no single-use nonce, and
    asks the authority nothing, so it checks no live revocation either. A
    service admits a call with ``codefly_hop.Verifier.verify``.

    A caller holding a call's headers extracts the token the stamp's digest
    binds with ``bound_token`` first. That is deliberately two calls (security
    review r164 R4): a reader taking headers reads as though it admitted the
    call, and it does not.
    """
    if not audience:
        raise Unauthenticated(Reason.CONFIGURATION)
    if len(token) > MAX_TOKEN_BYTES or not token.isascii() or token.count(".") != 1:
        raise Unauthenticated(Reason.MALFORMED)
    payload_segment, signature_segment = token.split(".")
    payload, signature = _canonical(payload_segment), _canonical(signature_segment)
    context = WorkContextV1()
    try:
        context.ParseFromString(payload)
    except DecodeError as error:
        raise Unauthenticated(Reason.MALFORMED) from None
    try:
        protovalidate.validate(_parsed(_CONTRACT, payload))
    except protovalidate.ValidationError as error:
        raise Unauthenticated(Reason.MALFORMED) from None
    context.DiscardUnknownFields()
    if context.SerializeToString(deterministic=True) != payload:
        raise Unauthenticated(Reason.MALFORMED)
    if context.expires_at_unix - context.not_before_unix > MAX_LIFETIME.total_seconds():
        raise Unauthenticated(Reason.LIFETIME)
    if context.issuer != trust.issuer:
        raise Unauthenticated(Reason.ISSUER)
    key = trust.keys.get(context.key_id)
    if key is None:
        raise Unauthenticated(Reason.UNKNOWNKEY)
    if trust.raw[context.key_id] == _FIXTURE_PUBLIC:
        raise Unauthenticated(Reason.FIXTUREKEY)
    try:
        key.verify(signature, payload)
    except InvalidSignature:
        raise Unauthenticated(Reason.SIGNATURE) from None
    if context.audience != audience:
        raise Unauthenticated(Reason.AUDIENCE)
    now = trust.now().timestamp()
    if now + SKEW.total_seconds() < context.not_before_unix:
        raise Unauthenticated(Reason.NOTYETVALID)
    if not now - SKEW.total_seconds() < context.expires_at_unix:
        raise Unauthenticated(Reason.EXPIRED)
    _check_structure(context)
    scopes = context.actor_chain[-1].granted_scopes if context.actor_chain else context.authority_scopes
    return Claims(
        audience=context.audience,
        scopes=tuple(Scope(s.resource_kind, tuple(s.actions), tuple(s.resource_ids), s.resource_owner_id) for s in scopes),
        context=context,
    )


def _parsed(cls, payload: bytes):
    message = cls()
    message.ParseFromString(payload)
    return message


def scope_contained(child, parents) -> bool:
    """Core's ScopeContained: per action, a whole-kind row covers it, or the
    child's ids all lie within the rows of that kind holding the action. A row
    naming an owner covers only a child naming the same owner."""
    if not any(parent.resource_kind == child.resource_kind for parent in parents):
        return False
    for action in child.actions:
        rows = [p for p in parents if p.resource_kind == child.resource_kind and action in p.actions
                and (not p.resource_owner_id or p.resource_owner_id == child.resource_owner_id)]
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
            raise Unauthenticated(Reason.ATTENUATION)
        effective = hop.granted_scopes
    if grant is None:
        return
    name = grant.grant_id
    if not chain:
        raise Unauthenticated(Reason.GRANT)
    if not context.HasField("parent_session_id"):
        raise Unauthenticated(Reason.GRANT)
    if context.replay_policy != REPLAY_SINGLE_USE:
        raise Unauthenticated(Reason.GRANT)
    scope = grant.granted_scope
    if len(scope.actions) != 1 or len(scope.resource_ids) != 1:
        raise Unauthenticated(Reason.GRANT)
    last = chain[-1]
    if len(last.granted_scopes) != 1 or last.granted_scopes[0] != scope:
        raise Unauthenticated(Reason.GRANT)
    if last.delegation_id != name:
        raise Unauthenticated(Reason.GRANT)
    actor = _identity(context, chain[-2]) if len(chain) > 1 else _identity(context)
    if _identity(context, last) != actor:
        raise Unauthenticated(Reason.GRANT)


def bound_token(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> str:
    """Extract a digest-bound token; this does not authenticate hop admission."""
    values = collect(headers)
    tokens, digests = values.get(WORK_CONTEXT_KEY, []), values.get(CONTEXT_KEY, [])
    if len(tokens) != 1 or not tokens[0] or len(digests) != 1:
        raise Unauthenticated(Reason.STAMPTOKEN)
    digest = hashlib.sha256(tokens[0].encode(errors="surrogatepass")).hexdigest()
    if not hmac.compare_digest(digest.encode(), digests[0].encode()):
        raise Unauthenticated(Reason.STAMPDIGEST)
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
        raise Unauthenticated(Reason.MALFORMED) from None
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise Unauthenticated(Reason.MALFORMED)
    return decoded
