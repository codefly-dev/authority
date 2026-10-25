import base64
import json
from pathlib import Path

import pytest
from google.protobuf import json_format

from authority_client._gen.host.authority.v1.authority_pb2 import KeysResponse
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from codefly_hop import (
    ACTORS_KEY, CONTEXT_KEY, SCOPES_KEY, TENANT_KEY, WORK_CONTEXT_KEY, Identity, Unauthenticated, Verifier, identity_of,
)

FIXTURE = json.loads((Path(__file__).parents[2] / "testdata/stamped.json").read_text())


class Keys:
    """The authority interface's Keys, as the generated stub answers it."""

    def __init__(self, response=None, error=None):
        self.response, self.error, self.reads, self.hold = response, error, 0, None

    def Keys(self, _request, timeout=None):
        assert timeout is not None, "a key read always carries a timeout"
        self.reads += 1
        if self.hold is not None and not self.hold.wait(timeout):
            raise TimeoutError("deadline exceeded")
        if self.error:
            raise self.error
        return self.response


def published():
    return json_format.ParseDict(FIXTURE["keys"], KeysResponse())


def verifier(clock=lambda: FIXTURE["now"], source=None):
    return Verifier(source or Keys(published()), audience=FIXTURE["audience"], proof=FIXTURE["proof"], now=clock)


def test_the_hop_fixture_authenticates_and_reads_as_go_reads_it():
    identity = verifier().verify(FIXTURE["headers"])
    want = FIXTURE["identity"]
    assert (identity.owner, identity.owner_kind, identity.tenant, identity.task, identity.expires) == (
        want["owner"], want["owner_kind"], want["tenant"], want["task"], want["expires"])
    assert identity.scopes == tuple(want["scopes"]) and identity.actors == tuple(want["actors"] or ())
    assert identity.advisory == want["advisory"]
    assert identity.context == FIXTURE["headers"][WORK_CONTEXT_KEY]
    assert identity.has("documents.collection", "read") and not identity.has("documents.collection", "write")
    assert identity.claims.allows("documents.collection", "write", "c-1")  # resource-exact, from the claims


# The defect: a module holding the proof writes the proof and any token's digest.
@pytest.mark.parametrize("change, reason", [
    ({TENANT_KEY: "globex"}, "tenant"),
    ({SCOPES_KEY: "documents.collection:read,documents.collection:admin"}, "scopes"),
    ({ACTORS_KEY: "robin"}, "actors"),
    ({"x-codefly-hop-proof": "another-run"}, "proof"),
    ({CONTEXT_KEY: "0" * 64}, "stamp binds"),
])
def test_a_stamp_the_token_does_not_bear_out_is_refused(change, reason):
    with pytest.raises(Unauthenticated, match=reason):
        verifier().verify({**FIXTURE["headers"], **change})


def test_a_token_the_authority_did_not_sign_is_refused_even_with_a_matching_digest():
    import hashlib
    token = FIXTURE["headers"][WORK_CONTEXT_KEY]
    forged = token.split(".")[0] + "." + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
    headers = {**FIXTURE["headers"], WORK_CONTEXT_KEY: forged, CONTEXT_KEY: hashlib.sha256(forged.encode()).hexdigest()}
    with pytest.raises(Unauthenticated, match="signature"):
        verifier().verify(headers)


def test_another_audience_and_an_expired_context_are_refused():
    with pytest.raises(Unauthenticated, match="minted for audience"):
        Verifier(Keys(published()), audience="records", proof=FIXTURE["proof"], now=lambda: FIXTURE["now"]).verify(FIXTURE["headers"])
    with pytest.raises(Unauthenticated, match="expired"):
        verifier(clock=lambda: FIXTURE["now"] + 3600, source=Keys(published())).verify(FIXTURE["headers"])


def settle(v):
    wait = v._inflight
    if wait is not None:
        wait.wait(5)


def test_keys_are_reread_when_old_and_trusted_no_longer_than_stale():
    clock = [FIXTURE["now"]]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    rotated = KeysResponse(issuer=published().issuer)
    rotated.keys.add(key_id="rotated", algorithm="Ed25519", public_key=bytes(32))
    source.response = rotated
    clock[0] += 400  # older than KEY_MAX_AGE: a re-read starts; the held key serves this call
    v.verify(FIXTURE["headers"])
    settle(v)
    assert source.reads == 2
    clock[0] += 11
    with pytest.raises(Unauthenticated, match="no verification key"):
        v.verify(FIXTURE["headers"])  # the authority no longer publishes it
    source.response, source.error = published(), RuntimeError("dial authority.internal:4000: connection refused")
    clock[0] += 1000
    with pytest.raises(Unauthenticated, match="unavailable") as refused:
        v.verify(FIXTURE["headers"])  # an unheld key waits for the read, which fails; the keys are stale
    assert "4000" not in str(refused.value) and "4000" in str(v.keys_error)


# Review r44 B1: nothing without the proof reaches the key read, and a hung read
# stalls no call whose key is held.
def test_a_call_without_the_proof_never_reads_the_keys():
    clock = [FIXTURE["now"]]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    for _ in range(20):
        clock[0] += 11
        for headers in ({WORK_CONTEXT_KEY: "garbage"}, {**FIXTURE["headers"], "x-codefly-hop-proof": "another-run"}):
            with pytest.raises(Unauthenticated):
                v.verify(headers)
    assert source.reads == 1


def test_a_hung_read_stalls_no_held_key():
    import threading
    import time as clock_time
    clock = [FIXTURE["now"]]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    source.hold = threading.Event()
    clock[0] += 400  # old keys: a background read starts and hangs
    started = clock_time.monotonic()
    assert v.verify(FIXTURE["headers"]).owner == FIXTURE["identity"]["owner"]
    assert clock_time.monotonic() - started < 1
    source.hold.set()


def test_a_verifier_starts_before_the_authority_serves_keys():
    clock = [FIXTURE["now"]]
    source = Keys(error=RuntimeError("connection refused"))
    v = Verifier(source, audience=FIXTURE["audience"], proof=FIXTURE["proof"], now=lambda: clock[0])
    with pytest.raises(Unauthenticated, match="unavailable"):
        v.verify(FIXTURE["headers"])
    source.error, source.response = None, published()
    clock[0] += 11
    assert v.verify(FIXTURE["headers"]).owner == FIXTURE["identity"]["owner"]


def test_identity_narrows_by_every_actor_and_never_widens_a_resource_scope():
    context = WorkContextV1(owner_principal_id="maya", tenant_id="acme")
    context.authority_scopes.add(resource_kind="documents", actions=["read", "write"])
    context.authority_scopes.add(resource_kind="records", actions=["read"], resource_ids=["r-1"])
    robin = context.actor_chain.add(principal_id="robin")
    robin.granted_scopes.add(resource_kind="documents", actions=["read"])
    model = context.actor_chain.add(principal_id="model")
    model.granted_scopes.add(resource_kind="documents", actions=["read"])
    identity = identity_of(context)
    assert identity.actors == ("robin", "model") and identity.scopes == ("documents:read",)
    context.actor_chain.add(principal_id="granted-nothing")
    assert identity_of(context).scopes == ()  # Core's EffectiveScopes: the last actor's grants


def test_a_verifier_needs_keys_an_audience_and_a_proof():
    for args in [(None, "documents", "p"), (Keys(published()), "", "p"), (Keys(published()), "documents", "")]:
        with pytest.raises(Unauthenticated):
            Verifier(args[0], audience=args[1], proof=args[2])
