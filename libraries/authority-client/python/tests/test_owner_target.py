"""TARGET (solution principal; conformance RunSolutionPrincipalTarget).

Run with AUTHORITY_TARGET=solution-principal. A module served in Python never
reads an owner-selected scope as the whole kind. The claims are built through
``authenticate`` from a signed context, so the decode path that projects
scopes keeps the owner: the owner-blind ``allows`` refuses an owner-selected
scope, and ``allows_owned`` admits a resource only for its owner (an owner
with ids only when both match; a plain scope names resources, not owners).
"""
import os

import pytest

from authority_client._gen.host.authority.v1.work_context_pb2 import WorkScopeV1
from authority_client.work_context import Unauthenticated, authenticate

from test_work_context import PROOF, body, sign, stamped, trust_for

pytestmark = pytest.mark.skipif(os.environ.get("AUTHORITY_TARGET") != "solution-principal",
                                reason="target contract, not yet implemented: run with AUTHORITY_TARGET=solution-principal")


def owned(context, kind, owner, *ids):
    """Adds {kind, [read], ids, resource_owner_id: owner}, the owner written as
    WorkScopeV1 field 4 until the generated code declares it."""
    raw = WorkScopeV1(resource_kind=kind, actions=["read"], resource_ids=list(ids)).SerializeToString()
    value = owner.encode()
    context.authority_scopes.add().MergeFromString(raw + bytes([(4 << 3) | 2, len(value)]) + value)


def test_claims_admit_an_owner_selected_scope_only_for_its_owner():
    context = body("session")
    del context.authority_scopes[:]
    owned(context, "record", "principal-u")
    owned(context, "note", "principal-u", "n1")
    context.authority_scopes.add(resource_kind="plain", actions=["read"])
    try:
        claims = authenticate(stamped(sign(context)), PROOF, context.audience, trust_for(context))
    except Unauthenticated as e:
        pytest.fail(f"target: a context with an owner-selected scope must authenticate: {e}")
    assert not claims.allows("record", "read") and not claims.allows("record", "read", "r1") and not claims.allows("note", "read", "n1"), \
        "target: the owner-blind allows admits an owner-selected scope"
    allows_owned = getattr(claims, "allows_owned", None)
    assert allows_owned is not None, "target: Claims has no allows_owned(kind, action, resource_id, owner_id)"
    for kind, resource, owner, allowed in [
        ("record", "r1", "principal-u", True), ("record", "r1", "principal-v", False), ("record", "r1", "", False),
        ("note", "n1", "principal-u", True), ("note", "n2", "principal-u", False), ("note", "n1", "principal-v", False),
        ("record", "", "principal-u", True), ("note", "", "principal-u", False),
        ("plain", "p1", "principal-u", True),
    ]:
        assert allows_owned(kind, "read", resource, owner) == allowed, (kind, resource, owner)
