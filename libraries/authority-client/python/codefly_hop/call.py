"""Signed hop admission v1. Replay consumption is supplied by the host, shared across replicas."""
import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from authority_client.work_context import Reason, Unauthenticated, collect


class Replayed(Exception):
    """The shared store has already consumed this nonce."""


class ReplayStore(Protocol):
    shared: bool  # true only for durable storage shared by every replica

    def consume(self, nonce: str, retain_until: int) -> None:
        """Atomically reserve nonce until Unix seconds; raise Replayed on reuse, another exception on unavailability.

        Every replica must use the same durable store. No process-local default.
        """
        ...

    async def consume_async(self, nonce: str, retain_until: int) -> None:
        """The same atomic operation without blocking the event loop."""
        ...


# The hop admission lifetime and the clock allowance, as Go's stamp.Lifetime
# and stamp.Skew define them. An admission may be issued up to SKEW ahead of
# this verifier's clock and stays admissible until SKEW past its expiry; the
# signed span is still capped at LIFETIME exactly.
LIFETIME, SKEW = 30, 2


# What a published admission key verifies: Keys carries the hop's keys in
# admission_keys with this purpose, never among the Work Context keys.
PURPOSE = "hop-admission"


def admission_keys(response) -> tuple[str, ...]:
    """The hop admission keys a KeysResponse publishes, hex: Ed25519 keys in
    ``admission_keys`` with purpose ``PURPOSE``; anything else there is not one."""
    out: list[str] = []
    for key in response.admission_keys:
        if key.algorithm != "Ed25519" or key.purpose != PURPOSE:
            continue
        if len(key.public_key) != 32:
            raise Unauthenticated(Reason.INVALIDKEY)
        if key.public_key.hex() not in out:
            out.append(key.public_key.hex())
    return tuple(out)


def _proof(values) -> tuple[bytes, bytes] | None:
    """The one admission the headers carry, as its signed payload and signature,
    each in canonical encoding; None for anything else."""
    items = values.get("x-codefly-hop-proof", [])
    if len(items) != 1 or len(items[0]) > 8192:
        return None
    parts = items[0].split(".")
    if len(parts) != 2:
        return None
    raw = []
    for value in parts:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            return None
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
            return None
        raw.append(decoded)
    return raw[0], raw[1]


def signed_by(headers, public_keys) -> str:
    """Which published admission key (hex) the admission is signed by, or ""
    for none: Go's stamp.SignedBy. ``check``, given that key, judges the rest."""
    proof = _proof(collect(headers))
    if proof is None:
        return ""
    for key in public_keys:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(proof[1], proof[0])
            return key
        except Exception:
            continue
    return ""


@dataclass(frozen=True)
class Call:
    nonce: str
    expires: int


def check(headers, public_key: str, method: str, audience: str, now: float) -> Call:
    values = collect(headers)

    def one(key):
        items = values.get(key, [])
        return items[0] if len(items) == 1 else ""

    try:
        proof = _proof(values)
        if proof is None:
            raise ValueError("encoding")
        payload, signature = proof
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(signature, payload)
        fields = json.loads(payload)
        if not isinstance(fields, list) or len(fields) != 7:
            raise ValueError("fields")
        domain, bound_method, bound_audience, digest, nonce, issued, expires = fields
        if any(not isinstance(v, str) for v in fields[:5]) or type(issued) is not int or type(expires) is not int:
            raise ValueError("types")
    except Exception as error:
        raise Unauthenticated(Reason.STAMPPROOF) from error
    if domain != "codefly-hop-v1":
        raise Unauthenticated(Reason.STAMPPROOF)
    if not method or method != bound_method:
        raise Unauthenticated(Reason.STAMPMETHOD)
    if not audience or audience != bound_audience:
        raise Unauthenticated(Reason.STAMPAUDIENCE)
    seconds = int(now)
    if issued < 0 or expires < 0:
        raise Unauthenticated(Reason.STAMPWINDOW)
    if issued > seconds + SKEW:
        raise Unauthenticated(Reason.STAMPISSUED)
    if expires + SKEW <= seconds or not 0 < expires - issued <= LIFETIME:
        raise Unauthenticated(Reason.STAMPWINDOW)
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise Unauthenticated(Reason.STAMPPROOF)
    tokens = values.get("x-codefly-work-context", [])
    if len(tokens) != 1 or not tokens[0]:
        raise Unauthenticated(Reason.STAMPTOKEN)
    if digest != hashlib.sha256(tokens[0].encode()).hexdigest() or one("x-codefly-hop-context") != digest:
        raise Unauthenticated(Reason.STAMPDIGEST)
    if "x-codefly-hop-advisory" in values:
        raise Unauthenticated(Reason.STAMPADVISORY)
    return Call("codefly-hop-v1:" + public_key + ":" + nonce, expires)


class Expired(Exception):
    """The reservation's retention had already passed when the store decided."""


class ReservationStore(ReplayStore, Protocol):
    """A store that holds a single-use admission while the call carrying it runs.

    The verifier reserves when the call arrives and finishes when its handler
    has returned; the store keeps the reservation until ``finish`` AND
    ``retain_until`` have both passed. ``reserve`` refuses atomically, across
    every replica, a nonce already held (``Replayed``), including one held by a
    call still running past its retention, and refuses a reservation whose
    ``retain_until`` has already passed by the store's clock (``Expired``): a
    reservation delayed past its own retention must never revive a nonce that
    was collected. A ``finish`` that fails leaves the reservation held.
    Because ``reserve`` refuses past ``retain_until`` on the store's clock, a
    store may collect a reservation once that has passed, finished or not.
    """
    def reserve(self, nonce: str, retain_until: int) -> None: ...
    def finish(self, nonce: str) -> None: ...
    async def reserve_async(self, nonce: str, retain_until: int) -> None: ...
    async def finish_async(self, nonce: str) -> None: ...
