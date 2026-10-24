"""The authority hop's stamp, as a module served in Python reads it.

The hop in front of a module asked the authority's Check, which verified the
caller's Work Context for the module and the method and applied what the method
declares, then wrote who the call is for onto the request: the stamp. A module
reads the stamp and verifies nothing itself. This is the Go library's ``Read``
(libraries/hop/go), rule for rule: the run's proof must match, the owner and the
tenant must be named, and a stamp bound to a Work Context is held to that exact
token. Both read the one fixture the hop writes (libraries/hop/testdata).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

WORK_CONTEXT_KEY = "x-codefly-work-context"
STAMP_PREFIX = "x-codefly-hop-"
PROOF_KEY = STAMP_PREFIX + "proof"
OWNER_KEY = STAMP_PREFIX + "owner"
OWNER_KIND_KEY = STAMP_PREFIX + "owner-kind"
TENANT_KEY = STAMP_PREFIX + "tenant"
ACTORS_KEY = STAMP_PREFIX + "actors"
SCOPES_KEY = STAMP_PREFIX + "scopes"
BINDING_KEY = STAMP_PREFIX + "binding"
CONTEXT_KEY = STAMP_PREFIX + "context"


class NoStamp(Exception):
    """The call did not come through the hop: it carries no stamp with this run's proof."""

    def __init__(self) -> None:
        super().__init__(
            "the call did not come through the hop: it carries no stamp with this run's proof"
        )


@dataclass(frozen=True)
class Identity:
    """Who a call is for, as the hop established it."""

    owner: str
    owner_kind: str
    tenant: str
    actors: tuple[str, ...] = ()
    # What the call may do, each "<resource kind>:<action>".
    scopes: tuple[str, ...] = ()
    # The operation binding the last actor exercises, when it names one.
    binding: str = ""
    # The Work Context the authority checked, as forwarded.
    context: str = field(default="", repr=False)

    def has(self, kind: str, action: str) -> bool:
        """Whether the call may do action on kind."""
        return f"{kind}:{action}" in self.scopes


def read(headers: Mapping[str, str] | Iterable[tuple[str, str]], proof: str) -> Identity:
    """The identity the hop stamped on headers, or NoStamp when they do not carry this
    run's proof. An empty proof is never accepted: a module with no proof delivered
    reads every call as one that bypassed the hop."""
    values = _collect(headers)
    got = _first(values, PROOF_KEY)
    if not proof or not got or not hmac.compare_digest(got.encode(), proof.encode()):
        raise NoStamp()
    owner, tenant = _first(values, OWNER_KEY), _first(values, TENANT_KEY)
    if not owner or not tenant:
        raise NoStamp()
    context = ""
    bound = _first(values, CONTEXT_KEY)
    if bound:
        tokens = values.get(WORK_CONTEXT_KEY, [])
        if len(tokens) != 1 or not hmac.compare_digest(_digest(tokens[0]).encode(), bound.encode()):
            raise NoStamp()
        context = tokens[0]
    return Identity(
        owner=owner,
        owner_kind=_first(values, OWNER_KIND_KEY),
        tenant=tenant,
        actors=_split(_first(values, ACTORS_KEY)),
        scopes=_split(_first(values, SCOPES_KEY)),
        binding=_first(values, BINDING_KEY),
        context=context,
    )


def _collect(headers: Mapping[str, str] | Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    # A header name is case-insensitive; a Starlette Headers or a WSGI environ
    # converted to pairs keeps repeats, which a single-value mapping cannot.
    pairs = headers.items() if isinstance(headers, Mapping) else headers
    values: dict[str, list[str]] = {}
    for key, value in pairs:
        values.setdefault(key.lower(), []).append(value)
    return values


def _first(values: dict[str, list[str]], key: str) -> str:
    found = values.get(key)
    return found[0] if found else ""


def _split(value: str) -> tuple[str, ...]:
    return tuple(value.split(",")) if value else ()


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
