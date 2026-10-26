"""Method-bound, single-use hop admission for Python services.

The hop alone holds a signing seed. Verifiers pin the delivered public key,
authenticate the Work Context and consume each signed nonce in a durable store
shared by all replicas. See libraries/hop/README.md for the wire contract.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from concurrent import futures
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .call import SKEW, Expired, Replayed, ReplayStore, ReservationStore, check
from authority_client._gen.host.authority.v1.authority_pb2 import KeysRequest
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from authority_client.work_context import Claims, Trust, Unauthenticated, Reason, authenticate_token, bound_token, collect

__all__ = ["Identity", "Verifier", "Unauthenticated", "Reason", "identity_of", "ReplayStore", "ReservationStore", "Replayed", "Expired"]

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


def _store_refusal(error: Exception) -> Unauthenticated:
    """The refusal a failed reservation answers: never the backend's error."""
    if isinstance(error, Unauthenticated):
        return error
    if isinstance(error, Replayed):
        return Unauthenticated(Reason.STAMPREPLAYED)
    if isinstance(error, Expired):
        return Unauthenticated(Reason.STAMPWINDOW)
    return Unauthenticated(Reason.STAMPSTORE)


def _within(until: int, arrival: float, mark: float) -> None:
    """A store without ``reserve`` keeps a nonce to its retention and may then
    evict it. A consumption that only succeeded because that retention had
    passed found an evicted nonce, not a new one: it is refused on the window,
    so a second delivery never runs."""
    if arrival + (time.monotonic() - mark) >= until:
        raise Unauthenticated(Reason.STAMPWINDOW)


class Verifier:
    """The one module-side entry point: authenticates every call the hop forwards.

    ``keys`` is the authority interface's generated ``AuthorityServiceStub`` (or
    anything with its ``Keys``): the published keys are read through it, never
    typed in. Build it once at startup; it never fails on an authority that is not
    serving yet, and refuses calls, with the reason, until the keys are read.
    """

    def __init__(self, keys, *, audience: str, public_key: str | None = None, replay: ReplayStore | None = None,
                 now: Callable[[], float] | None = None, timeout: float = KEY_TIMEOUT) -> None:
        admitting = public_key is not None or replay is not None
        if keys is None or not audience:
            raise Unauthenticated(Reason.CONFIGURATION)
        if admitting and (replay is None or not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-f]{64}", public_key)):
            # Admission needs both the delivered hop public key and a store
            # every replica shares; one without the other admits nothing.
            raise Unauthenticated(Reason.CONFIGURATION)
        if admitting and os.environ.get("CODEFLY__ENVIRONMENT") != "local" and getattr(replay, "shared", False) is not True:
            # A process-local store answers only for its own process: a captured
            # admission would replay once per replica, and a restart would
            # forget every reservation. Only the run named exactly "local" may.
            raise Unauthenticated(Reason.STORENOTSHARED)
        self._source, self._audience, self._timeout = keys, audience, timeout
        self._public_key, self._replay = public_key, replay
        self._now = now or time.time
        self._lock = threading.Lock()
        self._trust: Trust | None = None
        self._fetched = 0.0
        self._tried = float("-inf")
        self._inflight: futures.Future[None] | None = None  # done when the running read ends
        self.keys_error: Exception | None = None  # the last read's failure, for logs; never sent to a caller
        with self._lock:
            started = self._refresh()
        futures.wait((started,), timeout)

    def ready(self) -> bool:
        """Whether trusted keys are held: true from the first successful read and
        through failed re-reads inside the 15-minute window; false before any read
        succeeded or once the keys are stale. Readiness uses this, never
        ``keys_error``: a brief authority outage must not take a replica out of
        rotation while its keys are still trusted. It also starts the read a call
        would (keys missing or older than 5 min, at most every 10 s, never waiting),
        so an unready replica, which gets no calls, recovers, and an idle one never
        goes stale."""
        with self._lock:
            now = self._now()
            if (self._trust is None or now - self._fetched > KEY_MAX_AGE) and self._inflight is None and now - self._tried >= KEY_RETRY:
                self._refresh()
            return self._trust is not None and now - self._fetched <= KEY_STALE

    def verify(self, headers: Mapping[str, str] | Iterable[tuple[str, str]], method: str) -> Identity:
        """Who the call is for, or ``Unauthenticated`` naming why it is refused.
        The admission is checked first: nothing that is not signed for this exact
        method and audience reaches the key read, and its single-use nonce is
        reserved before the keys are read. It may wait up to the read's timeout
        for a key it does not hold yet, or for keys past the stale window; an
        asyncio handler uses ``verify_async``.

        The reservation's in-flight hold ends when ``verify`` returns, so it
        lasts to the admission's expiry plus the clock allowance. A handler
        whose work follows uses ``admit``, which holds it until that work ends."""
        identity, finish = self._admit(headers, method)
        finish()
        return identity

    @contextmanager
    def admit(self, headers: Mapping[str, str] | Iterable[tuple[str, str]], method: str):
        """``verify`` that holds the single-use reservation until the block
        exits, however it exits. Enter it as soon as the call's headers have
        arrived, before its body is read::

            with verifier.admit(metadata, method) as identity:
                ...  # the handler
        """
        identity, finish = self._admit(headers, method)
        try:
            yield identity
        finally:
            finish()

    async def verify_async(self, headers: Mapping[str, str] | Iterable[tuple[str, str]], method: str) -> Identity:
        """``verify`` for an asyncio handler: a wait for the keys is awaited on the
        event loop and holds no thread, so any number of waiting calls leave the
        loop's executor free; a call whose key is held never waits."""
        identity, finish = await self._admit_async(headers, method)
        await finish()
        return identity

    @asynccontextmanager
    async def admit_async(self, headers: Mapping[str, str] | Iterable[tuple[str, str]], method: str):
        """``admit`` for an asyncio handler."""
        identity, finish = await self._admit_async(headers, method)
        try:
            yield identity
        finally:
            await finish()

    def _admit(self, headers, method):
        pairs, token, call = self._bound(headers, method)
        arrival, mark = self._now(), time.monotonic()
        managed = callable(getattr(self._replay, "reserve", None))
        until = call.expires + SKEW
        try:
            if managed:
                self._replay.reserve(call.nonce, until)
            else:
                self._replay.consume(call.nonce, until)
        except Exception as error:
            raise _store_refusal(error) from error
        if not managed:
            _within(until, arrival, mark)

        def finish():
            if managed:
                try:
                    self._replay.finish(call.nonce)
                except Exception:
                    pass  # a failed release keeps the reservation held: never reopen
        try:
            wait = self._start(_key_id(token))
            if wait is not None:
                futures.wait((wait,), self._timeout)
            return self._finish(pairs, token), finish
        except BaseException:
            finish()
            raise

    async def _admit_async(self, headers, method):
        pairs, token, call = self._bound(headers, method)
        arrival, mark = self._now(), time.monotonic()
        managed = callable(getattr(self._replay, "reserve_async", None))
        until = call.expires + SKEW
        try:
            if managed:
                await self._replay.reserve_async(call.nonce, until)
            else:
                await self._replay.consume_async(call.nonce, until)
        except Exception as error:
            raise _store_refusal(error) from error
        if not managed:
            _within(until, arrival, mark)

        async def finish():
            if managed:
                try:
                    await self._replay.finish_async(call.nonce)
                except Exception:
                    pass  # a failed release keeps the reservation held: never reopen
        try:
            wait = self._start(_key_id(token))
            if wait is not None:
                try:
                    await asyncio.wait_for(asyncio.wrap_future(wait), self._timeout)
                except asyncio.TimeoutError:
                    pass  # judged below on the keys held: stale ones are refused with the reason
            return self._finish(pairs, token), finish
        except BaseException:
            await finish()
            raise

    def verify_token(self, token: str) -> Identity:
        """Authenticate a bare token with the same fail-closed key cache. It
        establishes no admission: no method binding is checked and no nonce is
        consumed, so a service admitting hop calls uses ``verify``."""
        wait = self._start(_key_id(token))
        if wait is not None:
            futures.wait((wait,), self._timeout)
        return self._token_identity(token)

    async def verify_token_async(self, token: str) -> Identity:
        """Async bare-token verification; never blocks the event loop."""
        wait = self._start(_key_id(token))
        if wait is not None:
            try:
                await asyncio.wait_for(asyncio.wrap_future(wait), self._timeout)
            except asyncio.TimeoutError:
                pass
        return self._token_identity(token)

    def _bound(self, headers, method):
        if self._public_key is None or self._replay is None:
            # A token-only verifier holds neither the hop's public key nor a
            # replay store, so it can establish no admission.
            raise Unauthenticated(Reason.CONFIGURATION)
        pairs = list(headers.items() if isinstance(headers, Mapping) else headers)
        call = check(pairs, self._public_key, method, self._audience, self._now())
        return pairs, bound_token(pairs), call

    def _start(self, key_id: str) -> futures.Future[None] | None:
        """Start a read when one is due; return it when this call must wait for it:
        its key is not held, or the held keys are past ``KEY_STALE`` (an idle
        replica's first call is judged on fresh keys, not refused while they
        arrive). Keys older than ``KEY_MAX_AGE`` but inside ``KEY_STALE`` are used
        while the read runs."""
        with self._lock:
            now = self._now()
            held = self._trust is not None and key_id in self._trust.keys
            if (not held or now - self._fetched > KEY_MAX_AGE) and self._inflight is None and now - self._tried >= KEY_RETRY:
                self._refresh()
            judgeable = held and now - self._fetched <= KEY_STALE
            return None if judgeable else self._inflight

    def _token_identity(self, token: str) -> Identity:
        with self._lock:
            if self._trust is None or self._now() - self._fetched > KEY_STALE:
                if isinstance(self.keys_error, Unauthenticated) and self.keys_error.reason == Reason.INVALIDKEY:
                    raise Unauthenticated(Reason.INVALIDKEY)
                raise Unauthenticated(Reason.KEYSUNAVAILABLE)
            trust = self._trust
        claims = authenticate_token(token, self._audience, trust)
        identity = identity_of(claims.context)
        return Identity(**{**identity.__dict__, "context": token, "claims": claims})

    def _finish(self, pairs: list[tuple[str, str]], token: str) -> Identity:
        identity = self._token_identity(token)
        values = collect(pairs)
        stamped = {
            OWNER_KEY: identity.owner, OWNER_KIND_KEY: identity.owner_kind, TENANT_KEY: identity.tenant,
            ACTORS_KEY: ",".join(identity.actors), SCOPES_KEY: ",".join(identity.scopes),
            BINDING_KEY: identity.binding, TASK_KEY: identity.task,
            EXPIRES_KEY: str(identity.expires) if identity.expires > 0 else "",
        }
        for key, want in stamped.items():
            got = values.get(key, [])
            if len(got) > 1 or (got[0] if got else "") != want:
                raise Unauthenticated(Reason.STAMPIDENTITY)
        # An admission carrying an advisory refusal is refused by ``check``, so
        # an admitted call never has one: diagnostic identity is never authority.
        return Identity(**{**identity.__dict__, "context": token, "advisory": "", "claims": identity.claims})

    def _refresh(self) -> futures.Future[None]:
        """Start the one read, on its own thread and timeout; the lock is held. The
        returned future is done when the read ends; it is running from the start,
        so a waiter that gives up (``wait_for`` cancelling its wrapper) cannot
        cancel it for the others."""
        if self._inflight is not None:
            return self._inflight
        done: futures.Future[None] = futures.Future()
        done.set_running_or_notify_cancel()
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
            done.set_result(None)

        threading.Thread(target=read, name="codefly-hop-keys", daemon=True).start()
        return done


def _key_id(token: str) -> str:
    """The key a token names, read only to choose the keys it is judged by."""
    if len(token) > 32 * 1024:
        return ""
    try:
        context = WorkContextV1()
        context.ParseFromString(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        return context.key_id
    except Exception:
        return ""


def _flatten(scopes) -> list[str]:
    out: list[str] = []
    for scope in scopes:
        # A resource-limited or owner-selected scope is never a kind-wide one.
        if scope.resource_ids or scope.resource_owner_id:
            continue
        for action in scope.actions:
            if f"{scope.resource_kind}:{action}" not in out:
                out.append(f"{scope.resource_kind}:{action}")
    return out
