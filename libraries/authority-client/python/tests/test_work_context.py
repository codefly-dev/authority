import base64
import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from authority_client.work_context import MAX_TOKEN_BYTES, Claims, Scope, UnreadableContext, read_claims as bound_claims
from codefly_hop import CONTEXT_KEY, WORK_CONTEXT_KEY, NoStamp, read

FIXTURES = json.loads((Path(__file__).parents[2] / "testdata/claims.json").read_text())
STAMP = json.loads((Path(__file__).parents[3] / "hop/testdata/stamped.json").read_text())


def read_claims(token):
    headers = dict(STAMP["headers"])
    headers[WORK_CONTEXT_KEY] = token
    headers[CONTEXT_KEY] = hashlib.sha256(token.encode(errors="surrogatepass")).hexdigest()
    return bound_claims(headers, STAMP["proof"])


def encoded(payload):
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def token_for(context):
    # Projection-only unit tests. These are not authenticated capabilities.
    return encoded(context.SerializeToString(deterministic=True)) + "." + encoded(bytes(64))


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f["name"])
def test_core_minted_and_verified_contexts_match_the_owner_projection(fixture):
    claims = read_claims(fixture["token"])
    assert claims.audience == fixture["audience"]
    assert claims.scopes == tuple(
        Scope(s["resource_kind"], tuple(s.get("actions", [])), tuple(s.get("resource_ids", [])))
        for s in fixture["scopes"]
    )
    for probe in fixture["probes"]:
        assert claims.allows(probe["kind"], probe["action"], probe["resource_id"]) == probe["allowed"]


def test_resource_ids_and_actions_are_never_combined_across_grants():
    context = WorkContextV1(audience="model")
    context.authority_scopes.add(resource_kind="profiles", actions=["read"], resource_ids=["a"])
    context.authority_scopes.add(resource_kind="profiles", actions=["invoke"], resource_ids=["b"])
    claims = read_claims(token_for(context))
    assert claims.allows("profiles", "read", "a")
    assert claims.allows("profiles", "invoke", "b")
    assert not claims.allows("profiles", "invoke", "a")
    assert not claims.allows("profiles", "read", "b")
    assert not claims.allows("profiles", "read")
    assert not claims.allows("other", "read", "a")
    with pytest.raises(FrozenInstanceError):
        claims.audience = "other"


def test_last_actor_grants_are_used_even_when_empty():
    context = WorkContextV1(audience="model")
    context.authority_scopes.add(resource_kind="profiles", actions=["read", "invoke"])
    first = context.actor_chain.add(principal_id="first")
    first.granted_scopes.add(resource_kind="profiles", actions=["read"], resource_ids=["a"])
    claims = read_claims(token_for(context))
    assert claims.allows("profiles", "read", "a")
    assert not claims.allows("profiles", "invoke", "a")
    assert not claims.allows("profiles", "read", "b")
    context.actor_chain.add(principal_id="last")
    assert read_claims(token_for(context)).scopes == ()


def test_kind_wide_grants_include_resources_without_action_implications():
    claims = Claims("model", (Scope("profiles", ("read", "admin", "*"), ()),))
    assert claims.allows("profiles", "read")
    assert claims.allows("profiles", "read", "a")
    assert not claims.allows("profiles", "invoke", "a")
    assert not claims.allows("profiles", "")
    assert not claims.allows("", "read")


@pytest.mark.parametrize("token", ["", "abc", "a.b.c", ".", "a.b", "a." + encoded(bytes(64)),
    "é.x", "\ud800.x", "a" * (MAX_TOKEN_BYTES + 1), encoded(b"{}") + "." + encoded(bytes(64)),
    token_for(WorkContextV1()), token_for(WorkContextV1(audience="model")) + "=",
])
def test_unreadable_envelopes_are_named(token):
    with pytest.raises(UnreadableContext):
        read_claims(token)


def test_unknown_nested_fields_and_duplicate_wire_fields_are_refused():
    context = WorkContextV1(audience="model")
    scope = context.authority_scopes.add(resource_kind="profiles", actions=["read"])
    scope.ParseFromString(scope.SerializeToString() + b"\x78\x01")
    with pytest.raises(UnreadableContext):
        read_claims(token_for(context))
    payload = WorkContextV1(audience="model").SerializeToString()
    with pytest.raises(UnreadableContext):
        read_claims(encoded(payload + payload) + "." + encoded(bytes(64)))


def test_resource_projection_uses_the_bound_token_and_never_the_flat_stamp():
    fixture = next(f for f in FIXTURES if f["name"] == "delegated")
    headers = dict(STAMP["headers"])
    headers[WORK_CONTEXT_KEY] = fixture["token"]
    headers[CONTEXT_KEY] = hashlib.sha256(fixture["token"].encode()).hexdigest()
    identity = read(headers, STAMP["proof"])
    claims = bound_claims(headers, STAMP["proof"])
    assert claims == read_claims(fixture["token"])
    assert not claims.allows("documents.collection", "read")  # advisory is not a grant
    other_token = next(f["token"] for f in FIXTURES if f["token"] != fixture["token"])
    for changed in [dict(headers, **{WORK_CONTEXT_KEY: other_token}),
                    list(headers.items()) + [(WORK_CONTEXT_KEY, fixture["token"])]]:
        with pytest.raises(NoStamp):
            read(changed, STAMP["proof"])
    headers.pop(CONTEXT_KEY)
    with pytest.raises(UnreadableContext):
        bound_claims(headers, STAMP["proof"])


def test_projection_does_not_claim_to_verify_signature():
    token = FIXTURES[0]["token"]
    assert read_claims(token) == read_claims(token.split(".")[0] + "." + encoded(bytes(64)))


@pytest.mark.parametrize("change", ["proof", "digest", "token", "duplicate", "missing"])
def test_reader_itself_refuses_an_unbound_token(change):
    headers = dict(STAMP["headers"])
    if change == "proof": headers["x-codefly-hop-proof"] = "forged"
    if change == "digest": headers[CONTEXT_KEY] = "0" * 64
    if change == "token": headers[WORK_CONTEXT_KEY] = FIXTURES[0]["token"]
    if change == "duplicate": headers = list(headers.items()) + [(WORK_CONTEXT_KEY,headers[WORK_CONTEXT_KEY])]
    if change == "missing": headers.pop(CONTEXT_KEY)
    with pytest.raises(UnreadableContext): bound_claims(headers,STAMP["proof"])


def test_reader_refuses_an_empty_proof():
    with pytest.raises(UnreadableContext): bound_claims(STAMP["headers"], "")
