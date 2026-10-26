"""The authority hop's stamp, as a module served in Python authenticates it.

The hop in front of a module asked the authority's Check, which verified the
caller's Work Context live and applied what the method declares, then wrote who
the call is for, this run's proof and the digest of the checked token: the
stamp. The module re-checks no permission the hop decided, but believes nothing
it has not authenticated. ``Verifier`` is the Go library's ``hop.Verifier``
(libraries/hop/go), rule for rule: the token is authenticated against the
authority's published keys (``authority_client.work_context.authenticate``), who
the call is for is read from its claims, and a stamp that says otherwise is
refused. Both read the one fixture the Go hop writes (libraries/hop/testdata).

It ships in the authority-client distribution, beside the ``authority_client``
package it rests on, so one pinned commit installs both and no dependency is
ever looked up by name on a public index.
"""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from authority_client._gen.host.authority.v1.authority_pb2 import KeysRequest
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from authority_client.work_context import Claims, Trust, Unauthenticated, authenticate, bound_token, collect

__all__ = ["Identity", "Verifier", "Unauthenticated", "identity_of"]

WORK_CONTEXT_KEY = "x-codefly-work-context"
STAMP_PREFIX = "x-codefly-hop-"
PROOF_KEY = STAMP_PREFIX + "proof"
OWNER_KEY = STAMP_PREFIX + "owner"
OWNER_KIND_KEY = STAMP_PREFIX + "owner-kind"
TENANT_KEY = STAMP_PREFIX + "tenant"
ACTORS_KEY = STAMP_PREFIX + "actors"
SCOPES_KEY = STAMP_PREFIX + "scopes"
BINDING_KEY = STAMP_PREFIX + "binding"
TASK_KEY = STAMP_PREFIX + "task"
EXPIRES_KEY = STAMP_PREFIX + "expires"
CONTEXT_KEY = STAMP_PREFIX + "context"
ADVISORY_KEY = STAMP_PREFIX + "advisory"

# The Go verifier's key policy: re-read on an unknown key at most every 10 s,
# and when older than 5 min, on a read of its own bounded by 5 s; unreadable
# keys are trusted no longer than 15 min.
KEY_RETRY, KEY_MAX_AGE, KEY_STALE, KEY_TIMEOUT = 10.0, 300.0, 900.0, 5.0


@dataclass(frozen=True)
class Identity:
    """Who a call is for, read from the authenticated Work Context."""

    owner: str
    owner_kind: str
    tenant: str
    actors: tuple[str, ...] = ()
    # Kind-wide effective scopes, each "<resource kind>:<action>"; claims.allows
    # answers resource-exact questions.
    scopes: tuple[str, ...] = ()
    binding: str = ""
    task: str = ""
    expires: int = 0
    # The authenticated Work Context, as forwarded.
    context: str = field(default="", repr=False)
    # The refusal the hop allowed in warning mode; diagnostic, grants nothing.
    advisory: str = ""
    claims: Claims | None = field(default=None, compare=False, repr=False)

    def has(self, kind: str, action: str) -> bool:
        """Whether the call may do action on the whole of kind."""
        return f"{kind}:{action}" in self.scopes


def identity_of(context) -> Identity:
    """The Go library's IdentityOf: owner authority narrowed by every actor's
    grant; resource-limited scopes are left out rather than widened."""
    scopes = _flatten(context.authority_scopes)
    actors = []
    for actor in context.actor_chain:
        actors.append(actor.principal_id)
        held = _flatten(actor.granted_scopes)  # an actor granted nothing narrows to nothing
        scopes = [s for s in scopes if s in held]
    return Identity(
        owner=context.owner_principal_id,
        owner_kind=context.owner_principal_kind,
        tenant=context.tenant_id,
        actors=tuple(actors),
        scopes=tuple(scopes),
        binding=context.operation_binding.binding_id,
        task=context.task_id,
        expires=int(context.expires_at_unix),
    )


class Verifier:
    """The one module-side entry point: authenticates every call the hop forwards.

    ``keys`` is the authority interface's generated ``AuthorityServiceStub`` (or
    anything with its ``Keys``): the published keys are read through it, never
    typed in. Build it once at startup; it never fails on an authority that is not
    serving yet, and refuses calls, with the reason, until the keys are read.
    """

    def __init__(self, keys, *, audience: str, proof: str, now: Callable[[], float] | None = None,
                 timeout: float = KEY_TIMEOUT) -> None:
        if keys is None or not audience or not proof:
            raise Unauthenticated("a verifier needs the authority's Keys, this module's audience and the run's hop proof")
        self._source, self._audience, self._proof, self._timeout = keys, audience, proof, timeout
        self._now = now or time.time
        self._lock = threading.Lock()
        self._trust: Trust | None = None
        self._fetched = 0.0
        self._tried = float("-inf")
        self._inflight: threading.Event | None = None
        self.keys_error: Exception | None = None  # the last read's failure, for logs; never sent to a caller
        with self._lock:
            started = self._refresh()
        started.wait(timeout)

    def ready(self) -> bool:
        """Whether trusted keys are held: true from the first successful read and
        through failed re-reads inside the 15-minute window; false before any read
        succeeded or once the keys are stale. Readiness uses this, never
        ``keys_error``: a brief authority outage must not take a replica out of
        rotation while its keys are still trusted."""
        with self._lock:
            return self._trust is not None and self._now() - self._fetched <= KEY_STALE

    def verify(self, headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> Identity:
        """Who the call is for, or ``Unauthenticated`` naming why it is refused.
        The stamp is checked first: nothing unbound reaches the key read. It may
        wait up to the read's timeout for a key it does not hold yet; an asyncio
        handler uses ``verify_async``."""
        pairs, token = self._bound(headers)
        wait = self._start(_key_id(token))
        if wait is not None:
            wait.wait(self._timeout)
        return self._finish(pairs, token)

    async def verify_async(self, headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> Identity:
        """``verify`` for an asyncio handler: a wait for the keys runs off the event
        loop, and a call whose key is held never leaves it."""
        pairs, token = self._bound(headers)
        wait = self._start(_key_id(token))
        if wait is not None:
            await asyncio.to_thread(wait.wait, self._timeout)
        return self._finish(pairs, token)

    def _bound(self, headers) -> tuple[list[tuple[str, str]], str]:
        pairs = list(headers.items() if isinstance(headers, Mapping) else headers)
        return pairs, bound_token(pairs, self._proof)

    def _start(self, key_id: str) -> threading.Event | None:
        """Start a read when one is due; return it when this call must wait for it."""
        with self._lock:
            now = self._now()
            held = self._trust is not None and key_id in self._trust.keys
            if (not held or now - self._fetched > KEY_MAX_AGE) and self._inflight is None and now - self._tried >= KEY_RETRY:
                self._refresh()
            return None if held else self._inflight

    def _finish(self, pairs: list[tuple[str, str]], token: str) -> Identity:
        with self._lock:
            if self._trust is None or self._now() - self._fetched > KEY_STALE:
                raise Unauthenticated("the authority's published keys are unavailable")
            trust = self._trust
        claims = authenticate(pairs, self._proof, self._audience, trust)
        values = collect(pairs)
        identity = identity_of(claims.context)
        stamped = {
            OWNER_KEY: identity.owner, OWNER_KIND_KEY: identity.owner_kind, TENANT_KEY: identity.tenant,
            ACTORS_KEY: ",".join(identity.actors), SCOPES_KEY: ",".join(identity.scopes),
            BINDING_KEY: identity.binding, TASK_KEY: identity.task,
            EXPIRES_KEY: str(identity.expires) if identity.expires > 0 else "",
        }
        for key, want in stamped.items():
            got = values.get(key, [])
            if len(got) > 1 or (got[0] if got else "") != want:
                raise Unauthenticated(f"the stamp's {key.removeprefix(STAMP_PREFIX)} does not match the authenticated Work Context")
        advisory = (values.get(ADVISORY_KEY) or [""])[0]
        return Identity(**{**identity.__dict__, "context": token, "advisory": advisory, "claims": claims})

    def _refresh(self) -> threading.Event:
        """Start the one read, on its own thread and timeout; the lock is held."""
        if self._inflight is not None:
            return self._inflight
        done = threading.Event()
        self._inflight, self._tried = done, self._now()

        def read() -> None:
            trust, error = None, None
            try:
                response = self._source.Keys(KeysRequest(), timeout=self._timeout)
                trust = Trust.from_keys(response, now=lambda: datetime.fromtimestamp(self._now(), timezone.utc))
            except Exception as failure:  # a gRPC error, a timeout, or keys that are unusable
                error = failure
            with self._lock:
                if trust is not None:
                    self._trust, self._fetched = trust, self._now()
                self.keys_error, self._inflight = error, None
            done.set()

        threading.Thread(target=read, name="codefly-hop-keys", daemon=True).start()
        return done


def _key_id(token: str) -> str:
    """The key a token names, read only to choose the keys it is judged by."""
    try:
        context = WorkContextV1()
        context.ParseFromString(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        return context.key_id
    except Exception:
        return ""


def _flatten(scopes) -> list[str]:
    out: list[str] = []
    for scope in scopes:
        if scope.resource_ids:
            continue
        for action in scope.actions:
            if f"{scope.resource_kind}:{action}" not in out:
                out.append(f"{scope.resource_kind}:{action}")
    return out
