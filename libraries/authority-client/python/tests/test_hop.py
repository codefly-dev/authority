import base64
import json
from pathlib import Path

import pytest
from google.protobuf import json_format

from authority_client._gen.host.authority.v1.authority_pb2 import KeysResponse
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from codefly_hop import (
    ACTORS_KEY, CONTEXT_KEY, KEY_RETRY, KEY_STALE, SCOPES_KEY, TENANT_KEY, WORK_CONTEXT_KEY, Identity, Unauthenticated,
    Verifier, identity_of,
)

FIXTURE = json.loads((Path(__file__).parents[3] / "hop/testdata/stamped.json").read_text())


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
    ({TENANT_KEY: "globex"}, "stamp_identity"),
    ({SCOPES_KEY: "documents.collection:read,documents.collection:admin"}, "stamp_identity"),
    ({ACTORS_KEY: "robin"}, "stamp_identity"),
    ({"x-codefly-hop-proof": "another-run"}, "proof"),
    ({CONTEXT_KEY: "0" * 64}, "stamp_digest"),
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
    with pytest.raises(Unauthenticated, match="audience"):
        Verifier(Keys(published()), audience="records", proof=FIXTURE["proof"], now=lambda: FIXTURE["now"]).verify(FIXTURE["headers"])
    with pytest.raises(Unauthenticated, match="expired"):
        verifier(clock=lambda: FIXTURE["now"] + 3600, source=Keys(published())).verify(FIXTURE["headers"])


def settle(v):
    wait = v._inflight
    if wait is not None:
        wait.result(5)


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


# The robin playground's model gateway, live: its first call after 39 idle
# minutes, with no readiness poll between, was refused while the re-read it
# started succeeded in the background. Held keys past KEY_STALE cannot judge a
# call, so the call waits for the read, as it does for a key not held. The keys
# are read before the fixture's token is minted, so the token is still live.
def test_a_call_on_keys_past_stale_waits_for_the_reread():
    clock = [FIXTURE["now"] - KEY_STALE - 60]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    clock[0] = FIXTURE["now"]
    assert v.verify(FIXTURE["headers"]).owner == FIXTURE["identity"]["owner"]
    assert source.reads == 2


# The wait on keys past KEY_STALE fails closed: a re-read that fails, or that
# outlives the read's timeout, refuses the call with the fixed reason, and only
# once the read has ended.
def test_a_call_on_keys_past_stale_is_refused_when_the_reread_fails():
    import threading
    import time as clock_time
    clock = [FIXTURE["now"] - KEY_STALE - 60]
    source = Keys(published())
    v = Verifier(source, audience=FIXTURE["audience"], proof=FIXTURE["proof"], now=lambda: clock[0], timeout=0.3)
    source.error, source.hold = RuntimeError("dial authority.internal:4000: connection refused"), threading.Event()
    clock[0] = FIXTURE["now"]
    outcome = []
    call = threading.Thread(target=lambda: outcome.append(_refusal(v)))
    call.start()
    call.join(0.1)
    assert call.is_alive(), f"the call was judged before its re-read ended: {outcome}"
    source.hold.set()
    call.join(5)
    assert "unavailable" in outcome[0] and "4000" not in outcome[0] and "4000" in str(v.keys_error)

    source.error, source.hold = None, threading.Event()  # a read that never answers
    clock[0] += KEY_RETRY
    started = clock_time.monotonic()
    refusal = _refusal(v)
    assert "unavailable" in refusal and clock_time.monotonic() - started >= 0.25
    settle(v)
    assert isinstance(v.keys_error, TimeoutError)


def _refusal(v):
    try:
        v.verify(FIXTURE["headers"])
    except Unauthenticated as refused:
        return str(refused)
    return "admitted"


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


# Review r57 m-b: an asyncio handler's wait for the keys never blocks the loop.
def test_verify_async_waits_for_keys_off_the_event_loop():
    import asyncio
    import threading

    clock = [FIXTURE["now"]]
    source = Keys(error=RuntimeError("not serving yet"))
    v = Verifier(source, audience=FIXTURE["audience"], proof=FIXTURE["proof"], now=lambda: clock[0], timeout=1.0)
    source.error, source.response, source.hold = None, published(), threading.Event()
    clock[0] += 11  # no key held: this call starts a read, which hangs, and waits for it

    async def scenario():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        running = asyncio.create_task(ticker())
        waiting = asyncio.create_task(v.verify_async(FIXTURE["headers"]))
        await asyncio.sleep(0.3)
        source.hold.set()
        identity = await waiting
        running.cancel()
        return ticks, identity

    ticks, identity = asyncio.run(scenario())
    assert ticks >= 10, "the event loop was blocked while the keys were read"
    assert identity.owner == FIXTURE["identity"]["owner"]


# Review r159 f2: verify_async waits for a re-read without a thread. Calls on
# keys past KEY_STALE, more than the default executor has workers, all wait for
# one hung re-read on a loop whose executor refuses work, and all verify once it
# lands; a call whose wait outlives the timeout is refused with the reason.
def test_verify_async_waits_for_a_stale_reread_without_a_thread():
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor

    class NoThreads(ThreadPoolExecutor):
        def submit(self, *args, **kwargs):
            raise AssertionError("verify_async took an executor thread to wait for the keys")

    clock = [FIXTURE["now"] - KEY_STALE - 60]
    source = Keys(published())
    v = Verifier(source, audience=FIXTURE["audience"], proof=FIXTURE["proof"], now=lambda: clock[0], timeout=1.0)
    source.hold = threading.Event()
    clock[0] = FIXTURE["now"]

    async def scenario():
        asyncio.get_running_loop().set_default_executor(NoThreads())
        calls = [asyncio.create_task(v.verify_async(FIXTURE["headers"])) for _ in range(64)]
        await asyncio.sleep(0.1)
        assert not any(call.done() for call in calls), "a call was judged before its re-read ended"
        source.hold.set()
        identities = await asyncio.gather(*calls)
        source.hold = threading.Event()  # the next re-read hangs past the timeout
        clock[0] += KEY_STALE + KEY_RETRY  # stale keys are refused before the token's own expiry is read
        try:
            await v.verify_async(FIXTURE["headers"])
        except Unauthenticated as refused:
            return identities, str(refused)
        return identities, "admitted"

    identities, refusal = asyncio.run(scenario())
    assert {identity.owner for identity in identities} == {FIXTURE["identity"]["owner"]} and len(identities) == 64
    assert source.reads == 3 and "unavailable" in refusal
    source.hold.set()


# Readiness follows trust, not the last read.
def test_ready_holds_while_keys_are_trusted():
    clock = [FIXTURE["now"]]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    assert v.ready()
    source.error = RuntimeError("authority down")
    clock[0] += 400  # old keys: ready() starts a re-read, which fails
    v.ready()
    settle(v)
    assert v.keys_error is not None and v.ready()
    clock[0] += 900
    assert not v.ready()


# Review r74 B1: an unready replica gets no calls; polling ready() alone must read
# again and turn it ready once the authority serves keys.
def test_an_unready_replica_becomes_ready_by_polling_alone():
    clock = [FIXTURE["now"]]
    source = Keys(error=RuntimeError("not serving yet"))
    v = Verifier(source, audience=FIXTURE["audience"], proof=FIXTURE["proof"], now=lambda: clock[0])
    ready = False
    for poll in range(30):
        if poll == 3:
            source.error, source.response = None, published()
        clock[0] += 1
        v.ready()
        settle(v)
        ready = v.ready()
        if ready:
            break
    assert ready and source.reads <= 3


# Review r74 B1: an idle replica polled for readiness past the stale window
# re-reads as its keys age and stays ready.
def test_an_idle_replica_polled_for_readiness_stays_ready():
    clock = [FIXTURE["now"]]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    for minute in range(60):
        clock[0] += 60
        v.ready()
        settle(v)
        assert v.ready(), f"an idle replica went unready at minute {minute + 1}"
    assert 10 <= source.reads <= 14


@pytest.mark.parametrize("row", json.loads((Path(__file__).parents[2] / "testdata/vectors.json").read_text()), ids=lambda r: r["name"])
def test_bare_token_matches_shared_verdict(row):
    response = KeysResponse(issuer=row["issuer"])
    for kid, raw in row["keys"].items():
        response.keys.add(key_id=kid, algorithm="Ed25519", public_key=base64.b64decode(raw))
    v = Verifier(Keys(response), audience=row["audience"], proof="proof", now=lambda: row["now"])
    if row["accept"]:
        assert v.verify_token(row["token"]).claims.audience == row["audience"]
    else:
        with pytest.raises(Unauthenticated) as refused:
            v.verify_token(row["token"])
        assert refused.value.code == row["reason"]
        assert row["token"] not in str(refused.value)


def test_bare_token_stale_wait_async_and_safe_reasons():
    import asyncio
    from codefly_hop import Reason
    codes = [r.value for r in Reason]
    assert len(set(codes)) == len(codes)
    assert len({Unauthenticated(r).text for r in Reason}) == len(codes)
    clock = [FIXTURE["now"] - KEY_STALE - 60]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    clock[0] = FIXTURE["now"]
    token = FIXTURE["headers"][WORK_CONTEXT_KEY]
    assert asyncio.run(v.verify_token_async(token)).owner == FIXTURE["identity"]["owner"]
    assert source.reads == 2
    clock[0] += KEY_STALE + 1
    source.error = RuntimeError("secret-key-source")
    with pytest.raises(Unauthenticated) as refused:
        v.verify_token(token)
    assert refused.value.code == Reason.KEYSUNAVAILABLE.value
    assert "secret" not in str(refused.value)

@pytest.mark.parametrize("change, code", [
    ({"x-codefly-hop-proof": "private-proof"}, "stamp_proof"),
    ({WORK_CONTEXT_KEY: ""}, "stamp_token"),
    ({CONTEXT_KEY: "private-digest"}, "stamp_digest"),
    ({TENANT_KEY: "private-tenant"}, "stamp_identity"),
])
def test_stamp_failure_codes_are_safe_and_distinct(change, code):
    with pytest.raises(Unauthenticated) as refused:
        verifier().verify({**FIXTURE["headers"], **change})
    assert refused.value.code == code
    assert "private-" not in str(refused.value)


def test_bare_only_process_needs_no_proof_and_cannot_accept_stamps():
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], now=lambda: FIXTURE["now"])
    assert v.verify_token(FIXTURE["headers"][WORK_CONTEXT_KEY]).owner == FIXTURE["identity"]["owner"]
    with pytest.raises(Unauthenticated):
        v.verify(FIXTURE["headers"])
