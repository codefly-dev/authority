"""What admitted a call, handed to the module so that no handler names a
permission. The Go library's ``admitted.go``, reading for reading.

The hop admits a call on its method's declaration and stamps, beside who the
call is for, everything the call holds with the selection each grant carries:
the whole kind, one owner's resources, or named resources (``ADMITTED_KEY``).
``Verifier`` holds that stamp to the Work Context it authenticated, reads the
method's declaration from the table the module hands it, and hands the handler
an ``Admission``: for what the method requires, and for what it carries, which
owners and which resources the call holds it on.

A handler that must narrow a query reads ``admitted(identity).required()`` (the
owners the caller may see) or ``.carried()`` (how far the narrower of two
declared scopes reaches, content against metadata), and writes no kind and no
action. Admission was decided by the hop; nothing here decides it again.

``testdata/stamps.json`` holds every reading here to Go's.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import NamedTuple

STAMP_PREFIX = "x-codefly-hop-"
# What the admitted call holds, each grant with its selection: encode_grants of
# Identity.grants. Like every stamp key it is the hop's to write: a caller's is
# stripped, and a module refuses one that is not what the authenticated Work
# Context says.
ADMITTED_KEY = STAMP_PREFIX + "admitted"
# The action a fixture grant holds every action with.
ANY_ACTION = "*"


class Permission(NamedTuple):
    """One action on one resource kind, carried apart and never joined and
    re-split: a kind is matched as it was declared."""

    kind: str
    action: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.action}"


@dataclass(frozen=True)
class Method:
    """One method's declaration (authority.hop.v1.Policy): every permission of
    ``requires``, or ``any_checked_caller`` and nothing. ``carries`` is what a
    call may exercise beyond what it requires; no decision reads it."""

    any_checked_caller: bool = False
    requires: tuple[Permission, ...] = ()
    carries: tuple[Permission, ...] = ()

    def declares(self) -> bool:
        """Whether the method declares anything at all."""
        return self.any_checked_caller or len(self.requires) > 0

    def valid(self) -> bool:
        """False for a declaration that says two things: any_checked_caller
        beside something a call must or may hold."""
        return not (self.any_checked_caller and len(self.requires) + len(self.carries) > 0)


@dataclass(frozen=True, order=True)
class Grant:
    """One action on one resource kind as the call holds it, with its
    selection: no owner and no resources is the whole kind; an owner alone is
    every resource that owner holds; resources are named resources, of owner
    when it is set. An action of ``ANY_ACTION`` holds every action."""

    kind: str
    action: str
    owner: str = ""
    resources: tuple[str, ...] = ()


def _canonical(grants: Iterable[Grant]) -> tuple[Grant, ...]:
    """Each grant once, its ids sorted and each once, the grants sorted by
    kind, action, owner, then ids. Strings order by code point, which is the
    order of their UTF-8 bytes Go sorts by."""
    return tuple(sorted({Grant(g.kind, g.action, g.owner, tuple(sorted(set(g.resources)))) for g in grants}))


def grants_held(context) -> tuple[Grant, ...]:
    """What a Work Context holds once every actor has narrowed it: the last
    actor's granted scopes, which the authority attenuated from each hop before
    it, or the owner's authority scopes when no one acts for them. One grant
    per action, canonical, so the hop and the module derive the same value."""
    scopes = context.actor_chain[-1].granted_scopes if len(context.actor_chain) > 0 else context.authority_scopes
    return _canonical(
        Grant(scope.resource_kind, action, scope.resource_owner_id, tuple(scope.resource_ids))
        for scope in scopes for action in scope.actions)


def encode_grants(grants: Iterable[Grant]) -> str:
    """``ADMITTED_KEY``'s value: unpadded base64url of a JSON array with one
    [kind, action, owner, [resource ids]] entry per grant, canonical, in the
    bytes Go's encoding/json writes (no spaces; ``<``, ``>``, ``&``, U+2028
    and U+2029 escaped), because a stamp is held to this value byte for byte."""
    raw = json.dumps([[g.kind, g.action, g.owner, list(g.resources)] for g in _canonical(grants)],
                     ensure_ascii=False, separators=(",", ":"))
    for plain, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        raw = raw.replace(plain, escaped)
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


_MALFORMED = "hop: the admission stamp is malformed"


def grants_of(value: str) -> tuple[Grant, ...]:
    """Decode ``ADMITTED_KEY``'s value, or ``ValueError``. It authenticates
    nothing: a module reads ``admitted``, which the Verifier established."""
    text = value.replace("\r", "").replace("\n", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        raise ValueError(_MALFORMED)
    try:
        entries = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace"))
    except ValueError as error:
        raise ValueError(_MALFORMED) from error
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise ValueError(_MALFORMED)
    text_of = lambda field: "" if field is None else field
    out = []
    for entry in entries:
        if not isinstance(entry, list) or len(entry) != 4:
            raise ValueError(_MALFORMED)
        kind, action, owner = (text_of(field) for field in entry[:3])
        ids = [] if entry[3] is None else entry[3]
        if not isinstance(ids, list):
            raise ValueError(_MALFORMED)
        ids = [text_of(i) for i in ids]
        if not all(isinstance(field, str) for field in (kind, action, owner, *ids)):
            raise ValueError(_MALFORMED)
        out.append(Grant(kind, action, owner, tuple(ids)))
    return tuple(out)


@dataclass(frozen=True)
class Named:
    """One term of a Selection: every resource of ``owner``, or the
    ``resources`` named, of ``owner`` when it is set. No owner and no
    resources is the whole kind."""

    owner: str = ""
    resources: tuple[str, ...] = ()


class Selection:
    """How far a call reaches for what its method declares: the union of its
    terms. ``Selection()`` reaches nothing."""

    __slots__ = ("_terms",)

    def __init__(self, terms: Iterable[Named] = ()) -> None:
        self._terms = tuple(terms)

    def __repr__(self) -> str:
        return f"Selection({list(self._terms)!r})"

    def empty(self) -> bool:
        """Whether the selection reaches nothing."""
        return len(self._terms) == 0

    def whole(self) -> bool:
        """Whether the call holds the declaration on the whole kind, with no
        owner selected. A module whose resources have owners decides for itself
        whether an unselected grant reaches them; ``owner_selected`` drops it."""
        return any(t.owner == "" and not t.resources for t in self._terms)

    def owners(self) -> list[str]:
        """The owners whose every resource the call reaches, sorted: what a
        list narrows its query to. Never None, so "no owner" is never read as
        "no filter"."""
        return sorted({t.owner for t in self._terms if t.owner != "" and not t.resources})

    def named(self) -> list[Named]:
        """The terms that name resources, for a module that honours them."""
        return [t for t in self._terms if t.resources]

    def owner_selected(self) -> "Selection":
        """The selection without the terms that name no owner: what a module
        reads when a grant that selects no owner must reach none of its owned
        resources."""
        return Selection(t for t in self._terms if t.owner != "")

    def allows(self, owner: str, id: str) -> bool:
        """Whether the selection reaches the resource ``id`` that ``owner``
        holds, as the module's own record names them. An empty id asks for
        every resource of that owner, which named resources never cover; a term
        naming an owner covers only that owner."""
        return any((t.owner == "" or t.owner == owner) and (not t.resources or (id != "" and id in t.resources))
                   for t in self._terms)


def _both(a: Selection, b: Selection) -> Selection:
    """The selection both a and b reach."""
    out: list[Named] = []
    for x in a._terms:
        for y in b._terms:
            if x.owner != "" and y.owner != "" and x.owner != y.owner:
                continue
            owner = x.owner or y.owner
            if not x.resources:
                resources = y.resources
            elif not y.resources:
                resources = x.resources
            else:
                resources = tuple(i for i in x.resources if i in y.resources)
                if not resources:
                    continue
            term = Named(owner, resources)
            if term not in out:
                out.append(term)
    return Selection(out)


@dataclass(frozen=True)
class Held:
    """One permission a method declares and how far the call holds it.
    ``carried`` is true for what the method carries rather than requires."""

    permission: Permission
    carried: bool
    selection: Selection


class Admission:
    """What admitted one call: the method (the procedure, or the HTTP request,
    the call was admitted on), what it declares, and how far the call holds
    each permission of that declaration.

    ``declared`` is false when the module declares nothing for the method that
    this verifier could read; nothing is then selected. ``any_checked_caller``
    is the method's declaration that it requires nothing: the call was admitted
    as a checked caller, on no scope at all. ``stamped`` is false only for the
    admission ``admitted`` answers when the hop stamped none."""

    __slots__ = ("method", "declared", "any_checked_caller", "stamped", "_held")

    def __init__(self, method: str = "", declared: bool = False, any_checked_caller: bool = False,
                 held: Iterable[Held] = (), stamped: bool = True) -> None:
        self.method, self.declared, self.any_checked_caller, self.stamped = method, declared, any_checked_caller, stamped
        self._held = tuple(held)

    def __repr__(self) -> str:
        return (f"Admission(method={self.method!r}, declared={self.declared}, "
                f"any_checked_caller={self.any_checked_caller}, stamped={self.stamped}, held={list(self._held)!r})")

    def required(self) -> Selection:
        """How far the call holds everything the method requires: the owners
        and resources on which it holds every required permission. A method
        that requires nothing selects nothing. When a method requires
        permissions of different kinds on named resources, read ``each``."""
        return self._all(False)

    def carried(self) -> Selection:
        """How far the call holds everything the method carries, within what
        it requires: the narrower of two declared scopes, such as content
        within metadata. Empty when the call holds only what the method
        requires."""
        if not any(h.carried for h in self._held):
            return Selection()
        carried = self._all(True)
        if any(not h.carried for h in self._held):
            return _both(self._all(False), carried)
        return carried

    def each(self) -> tuple[Held, ...]:
        """Every permission the method declares with its own selection, for
        the method that carries more than one thing. The permissions are the
        declaration's; a handler still writes none."""
        return self._held

    def _all(self, carried: bool) -> Selection:
        out: Selection | None = None
        for h in self._held:
            if h.carried == carried:
                out = h.selection if out is None else _both(out, h.selection)
        return Selection() if out is None else out


# What ``admitted`` answers for a call the hop stamped no admission on: it
# selects nothing, so a handler that narrows reaches nothing.
_NOTHING = Admission(stamped=False)


def admitted(identity) -> Admission:
    """What admitted the call ``Verifier`` authenticated, for a handler to
    narrow by. For a call the hop stamped no admission on (a hop older than
    this contract), and for no identity at all, it answers an admission that
    selects nothing, with ``stamped`` false; ``identity.admitted`` is then
    None. Never read an absent admission as "no filter"."""
    held = getattr(identity, "admitted", None)
    return _NOTHING if held is None else held


def admission_of(declared: Method, method: str, grants: Iterable[Grant]) -> Admission:
    """Read grants against one method's declaration: for each permission the
    method requires or carries, the selection of every grant that holds it. It
    is what the Verifier hands a handler; a test of a module's own narrowing
    builds one the same way."""
    if not declared.valid():
        # A declaration that says two things was refused by the hop; it is
        # never read as one of them here.
        return Admission(method, False, declared.any_checked_caller)
    canonical = _canonical(grants)
    held: list[Held] = []
    seen: set[Permission] = set()
    # What a method requires is read first: a permission it also lists as
    # carried is required.
    for carried, permissions in ((False, declared.requires), (True, declared.carries)):
        for permission in permissions:
            p = Permission(*permission)
            if p in seen:
                continue
            seen.add(p)
            held.append(Held(p, carried, Selection(
                Named(g.owner, g.resources) for g in canonical
                if g.kind == p.kind and (g.action == p.action or g.action == ANY_ACTION))))
    held.sort(key=lambda h: (h.carried, str(h.permission)))
    return Admission(method, declared.declares(), declared.any_checked_caller, held)


def declaration(declared: Mapping[str, Method] | None, method: str) -> Method:
    """What the module declares for method: an exact entry of the table it
    handed over, keyed "/package.Service/Method" or, for an HTTP route,
    "<VERB> <template>", or the one route template an HTTP request is an
    instance of. A method the table does not hold declares nothing."""
    declared = declared or {}
    if method in declared:
        return declared[method]
    verb, spaced, path = method.partition(" ")
    if spaced and path.startswith("/"):
        found = []
        for route, m in declared.items():
            want, spaced, template = route.partition(" ")
            if spaced and want == verb and _route_matches(template, path):
                found.append(m)
        # Two templates matching one request is the ambiguity the authority
        # refuses; it selects nothing here.
        if len(found) == 1:
            return found[0]
    return Method()


def _canonical_path(path: str) -> bool:
    """Go's routing.CanonicalPath: rooted, no dot segment, no repeated or
    trailing separator, no backslash and no escape."""
    if not path.startswith("/") or "\\" in path or "%" in path:
        return False
    return path == "/" or all(segment not in ("", ".", "..") for segment in path.split("/")[1:])


def _route_matches(template: str, path: str) -> bool:
    """Go's routing.RouteMatches, the hop's own template matcher: a final
    {name=**} spans at least one character; ordinary variables span one
    segment."""
    if not _canonical_path(path):
        return False
    want, got = template.split("/"), path.split("/")
    last = want[-1]
    if "=**}" in last:
        if len(got) < len(want):
            return False
        opened = last.find("{")
        if opened < 0:
            return False
        prefix, suffix = last[:opened], last[last.index("=**}") + 4:]
        rest = "/".join(got[len(want) - 1:])
        if not rest.startswith(prefix) or not rest.endswith(suffix) or len(rest) <= len(prefix) + len(suffix):
            return False
        want, got = want[:-1], got[:len(want) - 1]
    if len(want) != len(got):
        return False
    return all(_segment_matches(segment, got[i]) for i, segment in enumerate(want))


def _segment_matches(template: str, segment: str) -> bool:
    opened = template.find("{")
    if opened < 0:
        return template == segment
    end = template[opened:].find("}")
    if end < 0 or not segment.startswith(template[:opened]):
        return False
    rest, tail = segment[opened:], template[opened + end + 1:]
    return any(_segment_matches(tail, rest[i:]) for i in range(1, len(rest) + 1))
