"""Signed hop admission v1. Replay consumption is supplied by the host, shared across replicas."""
import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from authority_client.work_context import Unauthenticated, collect


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
        raise Unauthenticated("invalid hop proof signature or encoding") from error
    if domain != "codefly-hop-v1":
        raise Unauthenticated("unknown hop proof version")
    if not method or method != bound_method:
        raise Unauthenticated("hop proof method mismatch")
    if not audience or audience != bound_audience:
        raise Unauthenticated("hop proof audience mismatch")
    if issued < 0 or expires < 0 or issued > int(now) or expires <= int(now) or not 0 < expires - issued <= 30:
        raise Unauthenticated("hop proof expired or outside its validity window")
    if not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise Unauthenticated("invalid hop proof nonce")
    token = one("x-codefly-work-context")
    if not token or digest != hashlib.sha256(token.encode()).hexdigest() or one("x-codefly-hop-context") != digest:
        raise Unauthenticated("hop proof token digest mismatch")
    if "x-codefly-hop-advisory" in values:
        raise Unauthenticated("hop proof cannot authorize an advisory refusal")
    return Call("codefly-hop-v1:" + public_key + ":" + nonce, expires)
