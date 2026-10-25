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
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from authority_client._gen.host.authority.v1.authority_pb2 import KeysRequest
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from authority_client.work_context import Claims, Trust, Unauthenticated, authenticate, collect

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
# and when older than 5 min; unreadable keys are trusted no longer than 15 min.
KEY_RETRY, KEY_MAX_AGE, KEY_STALE = 10.0, 300.0, 900.0


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
        if actor.granted_scopes:
            held = _flatten(actor.granted_scopes)
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
    typed in. Build it once at startup.
    """

    def __init__(self, keys, *, audience: str, proof: str, now: Callable[[], float] | None = None) -> None:
        if keys is None or not audience or not proof:
            raise Unauthenticated("a verifier needs the authority's Keys, this module's audience and the run's hop proof")
        self._source, self._audience, self._proof = keys, audience, proof
        self._now = now or time.time
        self._lock = threading.Lock()
        self._trust: Trust | None = None
        self._fetched = self._tried = 0.0
        with self._lock:
            self._fetch()

    def verify(self, headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> Identity:
        """Who the call is for, or ``Unauthenticated`` naming why it is refused."""
        pairs = list(headers.items() if isinstance(headers, Mapping) else headers)
        values = collect(pairs)
        token = (values.get(WORK_CONTEXT_KEY) or [""])[0]
        claims = authenticate(pairs, self._proof, self._audience, self._trust_for(token))
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

    def _trust_for(self, token: str) -> Trust:
        with self._lock:
            now = self._now()
            held = self._trust is not None and _key_id(token) in self._trust.keys
            if (not held or now - self._fetched > KEY_MAX_AGE) and now - self._tried >= KEY_RETRY:
                try:
                    self._fetch()
                except Unauthenticated:
                    if now - self._fetched > KEY_STALE:
                        raise
            if now - self._fetched > KEY_STALE:
                raise Unauthenticated(f"the authority's keys were last read {int(now - self._fetched)}s ago")
            return self._trust

    def _fetch(self) -> None:
        self._tried = self._now()
        try:
            response = self._source.Keys(KeysRequest())
        except Exception as error:  # a gRPC error, or the stub's transport
            raise Unauthenticated(f"the authority's published keys cannot be read: {error}") from error
        self._trust = Trust.from_keys(response, now=lambda: datetime.fromtimestamp(self._now(), timezone.utc))
        self._fetched = self._tried


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
