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


@dataclass(frozen=True)
class Call:
    nonce: str
    expires: int


def check(headers, public_key: str, method: str, audience: str, now: float) -> Call:
    values = collect(headers)

    def one(key):
        items = values.get(key, [])
        return items[0] if len(items) == 1 else ""

    def segment(value):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("encoding")
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
            raise ValueError("encoding")
        return raw

    try:
        encoded = one("x-codefly-hop-proof")
        if len(encoded) > 8192:
            raise ValueError("size")
        payload, signature = (segment(part) for part in encoded.split("."))
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
