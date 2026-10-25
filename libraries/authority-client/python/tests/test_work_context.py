import base64
import hashlib
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from authority_client._gen.host.authority.v1.authority_pb2 import KeysResponse, PublicKey
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from authority_client.work_context import (
    CONTEXT_KEY, PROOF_KEY, WORK_CONTEXT_KEY, Claims, Scope, Trust, Unauthenticated, authenticate,
)

FIXTURES = json.loads((Path(__file__).parents[2] / "testdata/claims.json").read_text())
PROOF = "test-proof"
# The test authority: a key of the test's own, never Core's public fixture key.
SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(32))
PUBLIC = SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def body(name):
    token = next(f["token"] for f in FIXTURES if f["name"] == name)
    context = WorkContextV1()
    context.ParseFromString(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    return context


def sign(context, key=SIGNER):
    payload = context.SerializeToString(deterministic=True)
    return encoded(payload) + "." + encoded(key.sign(payload))


def trust_for(context, at=None):
    when = at or datetime.fromtimestamp(context.not_before_unix + 1, timezone.utc)
    keys = KeysResponse(issuer=context.issuer, keys=[PublicKey(key_id=context.key_id, algorithm="Ed25519", public_key=PUBLIC)])
    return Trust.from_keys(keys, now=lambda: when)


def stamped(token, proof=PROOF):
    return {WORK_CONTEXT_KEY: token, PROOF_KEY: proof, CONTEXT_KEY: hashlib.sha256(token.encode()).hexdigest()}


def read(context):
    return authenticate(stamped(sign(context)), PROOF, context.audience, trust_for(context))


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f["name"])
def test_core_minted_contexts_authenticate_and_project_the_owner_scopes(fixture):
    claims = read(body(fixture["name"]))
    assert claims.audience == fixture["audience"]
    assert claims.scopes == tuple(
        Scope(s["resource_kind"], tuple(s.get("actions", [])), tuple(s.get("resource_ids", [])))
        for s in fixture["scopes"]
    )
    for probe in fixture["probes"]:
        assert claims.allows(probe["kind"], probe["action"], probe["resource_id"]) == probe["allowed"]
    assert claims.context.tenant_id == body(fixture["name"]).tenant_id


def test_resource_ids_and_actions_are_never_combined_across_grants():
    context = body("session")
    del context.authority_scopes[:]
    context.authority_scopes.add(resource_kind="profiles", actions=["read"], resource_ids=["a"])
    context.authority_scopes.add(resource_kind="profiles", actions=["invoke"], resource_ids=["b"])
    claims = read(context)
    assert claims.allows("profiles", "read", "a") and claims.allows("profiles", "invoke", "b")
    assert not claims.allows("profiles", "invoke", "a") and not claims.allows("profiles", "read", "b")
    assert not claims.allows("profiles", "read") and not claims.allows("other", "read", "a")
    with pytest.raises(FrozenInstanceError):
        claims.audience = "other"


def test_kind_wide_grants_include_resources_without_action_implications():
    claims = Claims("model", (Scope("profiles", ("read", "admin", "*"), ()),))
    assert claims.allows("profiles", "read") and claims.allows("profiles", "read", "a")
    assert not claims.allows("profiles", "invoke", "a")
    assert not claims.allows("profiles", "") and not claims.allows("", "read")


# The defect this reader exists to close: whoever holds the run's proof writes the
# proof and the digest of any token. Only the signature, the issuer, the audience
# and the window make the token one the authority issued for this module, now.
def test_a_forged_or_misaddressed_context_is_refused_by_name():
    context = body("session")
    trust = trust_for(context)
    payload = sign(context).split(".")[0]
    foreign = WorkContextV1()
    foreign.CopyFrom(context)
    foreign.issuer = "https://forger.example"
    expired = trust_for(context, datetime.fromtimestamp(context.expires_at_unix, timezone.utc) + timedelta(hours=1))
    for token, audience, use, reason in [
        (sign(context, Ed25519PrivateKey.generate()), context.audience, trust, "signature"),
        (payload + "." + encoded(bytes(64)), context.audience, trust, "signature"),
        (sign(foreign), context.audience, trust, "issued by"),
        (sign(context), "another-module", trust, "minted for audience"),
        (sign(context), context.audience, trust_for(context, datetime.fromtimestamp(context.not_before_unix, timezone.utc) - timedelta(hours=1)), "not valid before"),
        (sign(context), context.audience, expired, "expired"),
        (sign(context), "", trust, "no audience"),
    ]:
        with pytest.raises(Unauthenticated, match=reason):
            authenticate(stamped(token), PROOF, audience, use)


@pytest.mark.parametrize("token", ["", "abc", "a.b.c", ".", "a." + encoded(bytes(64)), "é.x",
    encoded(b"{}") + "." + encoded(bytes(64))])
def test_unreadable_envelopes_are_refused(token):
    context = body("session")
    with pytest.raises(Unauthenticated):
        authenticate(stamped(token), PROOF, context.audience, trust_for(context))


@pytest.mark.parametrize("change", ["proof", "digest", "token", "duplicate", "missing", "empty proof"])
def test_the_reader_refuses_a_token_the_stamp_does_not_bind(change):
    context = body("session")
    token = sign(context)
    headers, proof = stamped(token), PROOF
    if change == "proof": headers[PROOF_KEY] = "forged"
    if change == "digest": headers[CONTEXT_KEY] = "0" * 64
    if change == "token": headers[WORK_CONTEXT_KEY] = sign(body("operation"))
    if change == "duplicate": headers = list(headers.items()) + [(WORK_CONTEXT_KEY, token)]
    if change == "missing": headers.pop(CONTEXT_KEY)
    if change == "empty proof": proof = ""
    with pytest.raises(Unauthenticated):
        authenticate(headers, proof, context.audience, trust_for(context))


def test_trust_comes_only_from_published_ed25519_keys():
    with pytest.raises(Unauthenticated, match="no issuer"):
        Trust.from_keys(KeysResponse(keys=[PublicKey(key_id="k", algorithm="Ed25519", public_key=PUBLIC)]))
    with pytest.raises(Unauthenticated, match="no verification key"):
        Trust.from_keys(KeysResponse(issuer="i", keys=[PublicKey(key_id="k", algorithm="RSA", public_key=PUBLIC)]))
    with pytest.raises(Unauthenticated, match="repeated"):
        Trust.from_keys(KeysResponse(issuer="i", keys=[PublicKey(key_id="k", algorithm="Ed25519", public_key=PUBLIC)] * 2))
    with pytest.raises(Unauthenticated, match="unusable"):
        Trust.from_keys(KeysResponse(issuer="i", keys=[PublicKey(key_id="k", algorithm="Ed25519", public_key=b"short")]))


VECTORS = json.loads((Path(__file__).parents[2] / "testdata/vectors.json").read_text())


# Go writes the vectors and its verdict on each (workcontext/vectors_test.go):
# this reader must reach the same verdict on every one, rule for rule.
@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
def test_python_reaches_gos_verdict_on_every_shared_vector(vector):
    keys = {kid: base64.b64decode(raw) for kid, raw in vector["keys"].items()}
    trust = Trust(vector["issuer"], keys, now=lambda: datetime.fromtimestamp(vector["now"], timezone.utc))
    headers = stamped(vector["token"])
    if vector["accept"]:
        authenticate(headers, PROOF, vector["audience"], trust)
    else:
        with pytest.raises(Unauthenticated) as refused:
            authenticate(headers, PROOF, vector["audience"], trust)
        assert vector["reason"] in str(refused.value)
