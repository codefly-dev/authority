"""TARGET (solution principal; conformance RunSolutionPrincipalTarget).

Run with AUTHORITY_TARGET=solution-principal. A module served in Python never
reads an owner-selected scope as the whole kind: the owner-blind ``allows``
refuses it, and ``allows_owned`` admits a resource only for its owner (an
owner with ids only when both match; a plain scope names resources, not
owners).
"""
import os

import pytest

from authority_client.work_context import Claims, Scope

pytestmark = pytest.mark.skipif(os.environ.get("AUTHORITY_TARGET") != "solution-principal",
                                reason="target contract, not yet implemented: run with AUTHORITY_TARGET=solution-principal")


def owned(kind, owner, *ids):
    try:
        return Scope(kind, ("read",), tuple(ids), resource_owner_id=owner)
    except TypeError as e:
        pytest.fail(f"target: Scope has no resource_owner_id: {e}")


def test_claims_admit_an_owner_selected_scope_only_for_its_owner():
    claims = Claims("store", (owned("record", "principal-u"), owned("note", "principal-u", "n1"), Scope("plain", ("read",), ())))
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
