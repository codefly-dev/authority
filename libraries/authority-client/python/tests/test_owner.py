"""The solution principal (conformance RunSolutionPrincipalTarget), read in Python.

A module served in Python never reads an owner-selected scope as the whole
kind. Claims are built through ``authenticate_token`` from a signed context, so the
decode path keeps the owner: the owner-blind ``allows`` refuses an
owner-selected scope, ``allows_owned`` admits a resource only for its owner,
the hop's identity leaves owner-selected scopes out, and a chain whose hop
drops or changes the owner is refused.
"""
import json
from pathlib import Path

import pytest

from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from authority_client.work_context import Unauthenticated, authenticate_token
from codefly_hop import identity_of

from test_work_context import PROOF, body, sign, stamped, trust_for


def claims_of(context):
    return authenticate_token(sign(context), context.audience, trust_for(context))


# The owner-selected rows (allows refusing, allows_owned admitting only the
# owner) are testdata/claims.json's "owner-selected" entry, run by
# test_work_context on the same rows as the Go and TypeScript readers.


def test_the_hop_identity_never_reads_an_owner_selected_scope_as_the_whole_kind():
    context = body("session")
    del context.authority_scopes[:]
    context.authority_scopes.add(resource_kind="record", actions=["read"], resource_owner_id="principal-u")
    assert "record:read" not in identity_of(context).scopes


@pytest.mark.parametrize("last, ok", [
    ({"resource_ids": ["r1"], "resource_owner_id": "principal-u"}, True),
    ({}, False),
    ({"resource_owner_id": "principal-v"}, False),
], ids=["narrowed within the owner", "the owner dropped", "the owner changed"])
def test_a_chain_that_drops_or_changes_the_owner_is_refused(last, ok):
    context = body("delegated")
    del context.authority_scopes[:]
    context.authority_scopes.add(resource_kind="record", actions=["read"], resource_owner_id="principal-u")
    for actor in context.actor_chain:
        del actor.granted_scopes[:]
        actor.granted_scopes.add(resource_kind="record", actions=["read"], resource_owner_id="principal-u")
    del context.actor_chain[-1].granted_scopes[:]
    context.actor_chain[-1].granted_scopes.add(resource_kind="record", actions=["read"], **last)
    if ok:
        claims_of(context)
    else:
        with pytest.raises(Unauthenticated):
            claims_of(context)


VECTORS = json.loads((Path(__file__).parents[2] / "testdata/resource_owner_vectors.json").read_text())


def _owner(vector):
    return vector["owner"] * vector.get("repeat", 1) if vector.get("repeat") else vector["owner"]


def _authenticates(owner):
    context = body("session")
    del context.authority_scopes[:]
    context.authority_scopes.add(resource_kind="record", actions=["read"], resource_owner_id=owner)
    claims_of(context)


@pytest.mark.parametrize("vector", VECTORS["accepted"], ids=lambda v: v["name"])
def test_core_accepted_owners_authenticate(vector):
    """Core's resource_owner_id rule, read from core's own vectors."""
    _authenticates(_owner(vector))


@pytest.mark.parametrize("vector", VECTORS["refused"], ids=lambda v: v["name"])
def test_core_refused_owners_do_not_authenticate(vector):
    with pytest.raises(Unauthenticated):
        _authenticates(_owner(vector))
