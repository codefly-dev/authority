import base64
import json
import hashlib
import secrets
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path

import pytest
from google.protobuf import json_format

from authority_client._gen.host.authority.v1.authority_pb2 import KeysResponse
from authority_client._gen.host.authority.v1.work_context_pb2 import WorkContextV1
from codefly_hop.call import SKEW
from codefly_hop import (
    ACTORS_KEY, CONTEXT_KEY, KEY_RETRY, KEY_STALE, SCOPES_KEY, TENANT_KEY, WORK_CONTEXT_KEY, Identity, Unauthenticated,
    Verifier, Replayed, Expired, identity_of,
)

FIXTURE = json.loads((Path(__file__).parents[3] / "hop/testdata/stamped.json").read_text())

METHOD = "/test.Service/Read"

class Replay:
    def __init__(self):
        self.seen, self.lock = set(), threading.Lock()
    def consume(self, nonce, until):
        with self.lock:
            if nonce in self.seen:
                raise Replayed()
            self.seen.add(nonce)
    async def consume_async(self, nonce, until):
        self.consume(nonce, until)

def fresh(now, *, method=METHOD, audience=FIXTURE["audience"], headers=None, issued=None, expires=None, hop=b"fixture-proof"):
    headers = dict(FIXTURE["headers"] if headers is None else headers)
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(hop).digest())
    payload = json.dumps(["codefly-hop-v1", method, audience,
        hashlib.sha256(headers[WORK_CONTEXT_KEY].encode()).hexdigest(), secrets.token_hex(32),
        int(now) if issued is None else issued, int(now)+30 if expires is None else expires], separators=(",", ":")).encode()
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    headers["x-codefly-hop-proof"] = encode(payload) + "." + encode(key.sign(payload))
    return headers


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
    return Verifier(source or Keys(published()), audience=FIXTURE["audience"], replay=Replay(), now=clock)


def test_the_hop_fixture_authenticates_and_reads_as_go_reads_it():
    identity = verifier().verify(FIXTURE["headers"], METHOD)
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
        verifier().verify({**FIXTURE["headers"], **change}, METHOD)


def test_a_token_the_authority_did_not_sign_is_refused_even_with_a_matching_digest():
    import hashlib
    token = FIXTURE["headers"][WORK_CONTEXT_KEY]
    forged = token.split(".")[0] + "." + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
    headers = {**FIXTURE["headers"], WORK_CONTEXT_KEY: forged, CONTEXT_KEY: hashlib.sha256(forged.encode()).hexdigest()}
    with pytest.raises(Unauthenticated, match="stamp_digest"):
        verifier().verify(headers, METHOD)


def test_another_audience_and_an_expired_context_are_refused():
    with pytest.raises(Unauthenticated, match="stamp_audience"):
        Verifier(Keys(published()), audience="records", replay=Replay(), now=lambda: FIXTURE["now"]).verify(FIXTURE["headers"], METHOD)
    with pytest.raises(Unauthenticated, match="expired"):
        verifier(clock=lambda: FIXTURE["now"] + 3600, source=Keys(published())).verify(FIXTURE["headers"], METHOD)


def settle(v):
    wait = v._inflight
    if wait is not None:
        wait.result(5)


def test_keys_are_reread_when_old_and_trusted_no_longer_than_stale():
    import threading

    clock = [FIXTURE["now"]]
    source = Keys(published())
    v = verifier(clock=lambda: clock[0], source=source)
    rotated = KeysResponse(issuer=published().issuer, admission_keys=published().admission_keys)
    rotated.keys.add(key_id="rotated", algorithm="Ed25519", public_key=bytes(32))
    source.response = rotated
    source.hold = threading.Event()
    clock[0] += 400  # older than KEY_MAX_AGE: a re-read starts; the held key serves this call
    try:
        v.verify(fresh(v._now()), METHOD)
    finally:
        source.hold.set()
    settle(v)
    assert source.reads == 2
    clock[0] += 11
    with pytest.raises(Unauthenticated, match="no verification key"):
        v.verify(fresh(v._now()), METHOD)  # the authority no longer publishes it
    source.response, source.error = published(), RuntimeError("dial authority.internal:4000: connection refused")
    clock[0] += 1000
    with pytest.raises(Unauthenticated, match="unavailable") as refused:
        v.verify(fresh(v._now()), METHOD)  # an unheld key waits for the read, which fails; the keys are stale
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
    assert v.verify(fresh(v._now()), METHOD).owner == FIXTURE["identity"]["owner"]
    assert source.reads == 2


# The wait on keys past KEY_STALE fails closed: a re-read that fails, or that
# outlives the read's timeout, refuses the call with the fixed reason, and only
# once the read has ended.
def test_a_call_on_keys_past_stale_is_refused_when_the_reread_fails():
    import threading
    import time as clock_time
    clock = [FIXTURE["now"] - KEY_STALE - 60]
    source = Keys(published())
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0], timeout=0.3)
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
        v.verify(fresh(v._now()), METHOD)
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
                v.verify(headers, METHOD)
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
    assert v.verify(fresh(v._now()), METHOD).owner == FIXTURE["identity"]["owner"]
    assert clock_time.monotonic() - started < 1
    source.hold.set()


def test_a_verifier_starts_before_the_authority_serves_keys():
    clock = [FIXTURE["now"]]
    source = Keys(error=RuntimeError("connection refused"))
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0])
    with pytest.raises(Unauthenticated, match="unavailable"):
        v.verify(fresh(v._now()), METHOD)
    source.error, source.response = None, published()
    clock[0] += 11
    assert v.verify(fresh(v._now()), METHOD).owner == FIXTURE["identity"]["owner"]


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


def test_a_verifier_needs_keys_and_an_audience():
    for args in [(None, "documents"), (Keys(published()), "")]:
        with pytest.raises(Unauthenticated):
            Verifier(args[0], audience=args[1], replay=Replay())


# Review r57 m-b: an asyncio handler's wait for the keys never blocks the loop.
def test_verify_async_waits_for_keys_off_the_event_loop():
    import asyncio
    import threading

    clock = [FIXTURE["now"]]
    source = Keys(error=RuntimeError("not serving yet"))
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0], timeout=1.0)
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
        waiting = asyncio.create_task(v.verify_async(fresh(v._now()), METHOD))
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
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0], timeout=1.0)
    source.hold = threading.Event()
    clock[0] = FIXTURE["now"]

    async def scenario():
        asyncio.get_running_loop().set_default_executor(NoThreads())
        calls = [asyncio.create_task(v.verify_async(fresh(v._now()), METHOD)) for _ in range(64)]
        await asyncio.sleep(0.1)
        assert not any(call.done() for call in calls), "a call was judged before its re-read ended"
        source.hold.set()
        identities = await asyncio.gather(*calls)
        source.hold = threading.Event()  # the next re-read hangs past the timeout
        clock[0] += KEY_STALE + KEY_RETRY  # stale keys are refused before the token's own expiry is read
        try:
            await v.verify_async(fresh(v._now()), METHOD)
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
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0])
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


# Independent review probes: method retargeting, cross-audience use, replay on
# another replica, and a workload constructing the old shared-proof stamp.
def test_review_retargeting_and_replay_across_replicas():
    store = Replay()
    first = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store, now=lambda: FIXTURE["now"])
    second = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store, now=lambda: FIXTURE["now"])
    headers = FIXTURE["headers"]
    for method in ("/documents.v1.Service/Delete", "/datasets.v1.Service/Register", "Read", "", "POST " + METHOD):
        with pytest.raises(Unauthenticated, match="stamp_method"):
            first.verify(headers, method)
    other = Verifier(Keys(published()), audience="records", replay=store, now=lambda: FIXTURE["now"])
    with pytest.raises(Unauthenticated, match="stamp_audience"):
        other.verify(headers, METHOD)
    assert first.verify(headers, METHOD).claims.context.replay_policy == "single-use"
    for replica in (first, second):
        with pytest.raises(Unauthenticated, match="stamp_replayed"):
            replica.verify(headers, METHOD)
    with pytest.raises(Unauthenticated, match="proof"):
        second.verify({**headers, "x-codefly-hop-proof": "fixture-proof"}, METHOD)


def test_review_concurrent_replay_and_store_failure():
    from concurrent.futures import ThreadPoolExecutor
    v = verifier()
    def attempt(_):
        try:
            v.verify(FIXTURE["headers"], METHOD)
            return 1
        except Unauthenticated:
            return 0
    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(attempt, range(32))) == 1
    class Down(Replay):
        def consume(self, nonce, until):
            raise OSError("store down")
    v._replay = Down()
    with pytest.raises(Unauthenticated, match="stamp_store"):
        v.verify(fresh(FIXTURE["now"]), METHOD)


@pytest.mark.parametrize("issued,expires,code", [
    ((0, 30, "stamp_window")),
    # Issued further ahead than the clock allowance: its own reason, so a
    # verifier running behind is not diagnosed as an expiry.
    ((FIXTURE["now"] + SKEW + 1, FIXTURE["now"] + 30, "stamp_issued")),
    # The allowance widens no span: 31 seconds is refused however clocks sit.
    ((FIXTURE["now"], FIXTURE["now"] + 31, "stamp_window")),
])
def test_signed_admission_window_is_bounded(issued, expires, code):
    with pytest.raises(Unauthenticated) as refused:
        verifier().verify(fresh(FIXTURE["now"], issued=issued, expires=expires), METHOD)
    assert refused.value.code == code


# Review r164 R1: a verifier whose clock lags the hop refused genuine calls
# whenever the signing instant fell just after a second boundary, under a reason
# that read as an expiry. Go, Python and TypeScript allow the same SKEW.
@pytest.mark.parametrize("lag", [0, 1, SKEW])
def test_a_clock_difference_inside_the_allowance_still_admits(lag):
    identity = verifier(clock=lambda: FIXTURE["now"] - lag).verify(fresh(FIXTURE["now"]), METHOD)
    assert identity.owner == FIXTURE["identity"]["owner"]


@pytest.mark.parametrize("lag,code", [(SKEW + 1, "stamp_issued"), (-(30 + SKEW), "stamp_window")])
def test_a_clock_difference_beyond_the_allowance_is_refused(lag, code):
    with pytest.raises(Unauthenticated) as refused:
        verifier(clock=lambda: FIXTURE["now"] - lag).verify(fresh(FIXTURE["now"]), METHOD)
    assert refused.value.code == code


# Review r164 R2: the reservation outlives the admission by the same allowance,
# so a store evicting on its own clock cannot release a nonce a lagging verifier
# would still admit.
def test_a_reservation_is_retained_past_expiry_by_the_allowance():
    retained = []

    class Recording:
        def consume(self, nonce, retain_until):
            retained.append(retain_until)

    v = verifier()
    v._replay = Recording()
    headers = fresh(FIXTURE["now"])
    payload = json.loads(base64.urlsafe_b64decode(
        headers["x-codefly-hop-proof"].split(".")[0] + "=" * (-len(headers["x-codefly-hop-proof"].split(".")[0]) % 4)))
    v.verify(headers, METHOD)
    assert retained == [payload[6] + SKEW]


def test_duplicate_proof_and_token_are_refused_before_consumption():
    for key in ("x-codefly-hop-proof", WORK_CONTEXT_KEY, CONTEXT_KEY):
        v = verifier()
        with pytest.raises(Unauthenticated):
            v.verify(list(FIXTURE["headers"].items()) + [(key, FIXTURE["headers"][key])], METHOD)
        v.verify(FIXTURE["headers"], METHOD)


def test_async_replay_has_one_winner_across_replicas():
    import asyncio
    store = Replay()
    replicas = [Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store, now=lambda: FIXTURE["now"]) for _ in range(2)]
    async def run():
        return await asyncio.gather(*(replicas[n % 2].verify_async(FIXTURE["headers"], METHOD) for n in range(32)), return_exceptions=True)
    results = asyncio.run(run())
    assert sum(isinstance(result, Identity) for result in results) == 1
    assert sum(isinstance(result, Unauthenticated) for result in results) == 31

@pytest.mark.parametrize("row", json.loads((Path(__file__).parents[2] / "testdata/vectors.json").read_text()), ids=lambda r: r["name"])
def test_bare_token_matches_shared_verdict(row):
    response = KeysResponse(issuer=row["issuer"])
    for kid, raw in row["keys"].items():
        response.keys.add(key_id=kid, algorithm="Ed25519", public_key=base64.b64decode(raw))
    v = Verifier(Keys(response), audience=row["audience"], now=lambda: row["now"])
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
        verifier().verify({**FIXTURE["headers"], **change}, METHOD)
    assert refused.value.code == code
    assert "private-" not in str(refused.value)


def test_bare_only_process_needs_no_admission_keys_and_cannot_accept_stamps():
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], now=lambda: FIXTURE["now"])
    assert v.verify_token(FIXTURE["headers"][WORK_CONTEXT_KEY]).owner == FIXTURE["identity"]["owner"]
    # Without the hop public key and a shared replay store it admits nothing.
    with pytest.raises(Unauthenticated, match="configuration"):
        v.verify(FIXTURE["headers"], METHOD)


def test_invalid_publication_and_unreadable_keys_have_distinct_safe_codes():
    for source, code in [(Keys(KeysResponse(issuer="issuer")), "invalid_key"),
                         (Keys(error=RuntimeError("private-source-detail")), "keys_unavailable")]:
        v = verifier(source=source)
        with pytest.raises(Unauthenticated) as refused:
            v.verify_token(FIXTURE["headers"][WORK_CONTEXT_KEY])
        assert refused.value.code == code
        assert "private-" not in str(refused.value)


class Reservations:
    """A reservation store as replaypg is: a nonce is held until it is finished
    AND its retention has passed, and a reservation past its retention is
    refused rather than inserted. ``collect`` removes what has aged out."""

    shared = True

    def __init__(self, clock):
        self.clock, self.held, self.active = clock, {}, set()

    def reserve(self, nonce, until):
        if until <= self.clock():
            raise Expired()
        if nonce in self.held:
            raise Replayed()
        self.held[nonce] = until
        self.active.add(nonce)

    def finish(self, nonce):
        self.active.discard(nonce)

    async def reserve_async(self, nonce, until):
        self.reserve(nonce, until)

    async def finish_async(self, nonce):
        self.finish(nonce)

    def consume(self, nonce, until):
        raise AssertionError("a reservation store is reserved, never consumed")

    async def consume_async(self, nonce, until):
        self.consume(nonce, until)

    def collect(self):
        for nonce, until in list(self.held.items()):
            if nonce not in self.active and until < self.clock():
                del self.held[nonce]


# Review of #28 at 8a3e953b: a single-use admission is consumed exactly once.
# Two deliveries of one admission arrive inside its window; the first holds its
# reservation while its handler runs, past its retention and collection; the
# second is refused by name, and so is a delivery after the handler returned.
def test_a_second_delivery_of_one_admission_is_refused_while_and_after_the_first_runs():
    clock = [FIXTURE["now"]]
    store = Reservations(lambda: clock[0])
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store,
                 now=lambda: clock[0])
    headers = fresh(FIXTURE["now"])
    ran = 0
    with v.admit(headers, METHOD) as identity:
        ran += 1
        assert identity.owner == FIXTURE["identity"]["owner"]
        with pytest.raises(Unauthenticated, match="stamp_replayed"):
            v.verify(headers, METHOD)
        clock[0] += 30 + SKEW + 5  # past the retention while the handler still runs
        store.collect()
        assert store.held, "collection removed the reservation of a running call"
        with pytest.raises(Unauthenticated) as refused:
            with v.admit(headers, METHOD):
                ran += 1
        assert refused.value.code == "stamp_window"
    store.collect()
    assert not store.held and ran == 1


# The reservation is taken before the Work Context is authenticated, so a
# refusal there ends the hold rather than leaving it pinned, and a second
# delivery still meets the reservation. An admission that cannot be judged,
# because no keys are held, reserves nothing.
def test_the_reservation_is_taken_before_the_work_context_and_released_on_refusal():
    clock = [FIXTURE["now"]]
    store = Reservations(lambda: clock[0])
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store,
                 now=lambda: clock[0])
    token = FIXTURE["headers"][WORK_CONTEXT_KEY]
    forged = token.split(".")[0] + "." + base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode()
    headers = fresh(FIXTURE["now"], headers={**FIXTURE["headers"], WORK_CONTEXT_KEY: forged,
                                            CONTEXT_KEY: hashlib.sha256(forged.encode()).hexdigest()})
    with pytest.raises(Unauthenticated, match="signature"):
        v.verify(headers, METHOD)
    assert list(store.held) and not store.active, "a refused call kept its hold, or never reserved"
    with pytest.raises(Unauthenticated, match="stamp_replayed"):
        v.verify(headers, METHOD)
    unread = Reservations(lambda: clock[0])
    down = Verifier(Keys(error=RuntimeError("authority down")), audience=FIXTURE["audience"], replay=unread,
                    now=lambda: clock[0], timeout=0.05)
    with pytest.raises(Unauthenticated, match="keys"):
        down.verify(fresh(FIXTURE["now"]), METHOD)
    assert not unread.held, "an admission judged on no keys was reserved"


def test_admit_releases_its_hold_however_the_handler_ends():
    clock = [FIXTURE["now"]]
    store = Reservations(lambda: clock[0])
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store,
                 now=lambda: clock[0])
    with pytest.raises(ZeroDivisionError):
        with v.admit(fresh(FIXTURE["now"]), METHOD):
            assert store.active
            1 / 0
    assert store.held and not store.active


def test_admit_async_holds_the_reservation_until_the_handler_returns():
    import asyncio
    clock = [FIXTURE["now"]]
    store = Reservations(lambda: clock[0])
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store,
                 now=lambda: clock[0])
    headers = fresh(FIXTURE["now"])

    async def run():
        async with v.admit_async(headers, METHOD):
            assert store.active
            with pytest.raises(Unauthenticated, match="stamp_replayed"):
                await v.verify_async(headers, METHOD)
        assert not store.active
    asyncio.run(run())


# A store without reserve keeps a nonce to its retention and may then evict it.
# A delivery that arrived inside the window, but whose consumption completed
# after the retention, found an evicted nonce: it is refused on the window.
def test_a_consumption_completing_past_its_retention_is_refused(monkeypatch):
    import time as clock_module
    real, slow = clock_module.monotonic, [0]
    monkeypatch.setattr(clock_module, "monotonic", lambda: real() + slow[0])

    class Evicted:
        """Every nonce has been evicted; the second consumption takes a minute."""
        def __init__(self):
            self.calls = 0
        def consume(self, nonce, until):
            self.calls += 1
            slow[0] = 60 if self.calls == 2 else slow[0]

    v = verifier()
    v._replay = Evicted()
    v.verify(fresh(FIXTURE["now"]), METHOD)
    with pytest.raises(Unauthenticated) as refused:
        v.verify(fresh(FIXTURE["now"]), METHOD)
    assert refused.value.code == "stamp_window"


# Outside the run named exactly "local", a store that does not declare itself
# the durable one every replica shares is refused at startup, as Go refuses it.
@pytest.mark.parametrize("environment", [None, "", "production", "staging", "local-production", "local-docker", " local", "local ", "local"])
def test_startup_requires_a_shared_store_outside_exactly_local(monkeypatch, environment):
    if environment is None:
        monkeypatch.delenv("CODEFLY__ENVIRONMENT", raising=False)
    else:
        monkeypatch.setenv("CODEFLY__ENVIRONMENT", environment)
    if environment == "local":
        verifier()
    else:
        with pytest.raises(Unauthenticated) as refused:
            verifier()
        assert refused.value.code == "replay_store_not_shared"
    store = Replay()
    store.shared = True
    Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store)
    Verifier(Keys(published()), audience=FIXTURE["audience"])  # a token-only verifier holds no store


def hop_key(label: bytes):
    """The admission key of the test hop that signs as label, as Keys publishes it."""
    from authority_client._gen.host.authority.v1.authority_pb2 import PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label).digest()).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return PublicKey(key_id="hop-" + label.decode(), algorithm="Ed25519", public_key=raw, purpose="hop-admission")


def publishing(*labels: bytes) -> KeysResponse:
    """The fixture's Work Context keys, and the admission keys of these hops."""
    response = published()
    del response.admission_keys[:]
    response.admission_keys.extend(hop_key(label) for label in labels)
    return response


# Review r3 B1: the hop's admission key comes from the authority's Keys, the
# read the verifier already makes; nothing about the hop is configured.
def test_a_verifier_takes_the_hops_key_from_the_authoritys_keys_alone():
    v = Verifier(Keys(publishing(b"the-hop")), audience=FIXTURE["audience"], replay=Replay(), now=lambda: FIXTURE["now"])
    assert v.verify(fresh(FIXTURE["now"], hop=b"the-hop"), METHOD).owner == FIXTURE["identity"]["owner"]


# A stamp signed by a key the authority does not publish is refused by name,
# and causes no read of the authority's keys.
def test_a_stamp_signed_by_an_unpublished_key_is_refused_by_name():
    source = Keys(publishing(b"the-hop"))
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: FIXTURE["now"])
    settle(v)
    reads = source.reads
    with pytest.raises(Unauthenticated) as refused:
        v.verify(fresh(FIXTURE["now"], hop=b"an-unpublished-hop"), METHOD)
    assert refused.value.code == "stamp_proof"
    settle(v)
    assert source.reads == reads


# While a hop's key rotates both are published and admitted; once the retiring
# key is withdrawn, the next read stops admitting it.
def test_a_rotations_overlap_admits_both_keys_until_the_retiring_one_is_withdrawn():
    clock = [FIXTURE["now"]]
    source = Keys(publishing(b"retiring", b"current"))
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0])
    for hop in (b"retiring", b"current"):
        v.verify(fresh(clock[0], hop=hop), METHOD)
    source.response = publishing(b"current")
    clock[0] += 301  # past KEY_MAX_AGE: readiness re-reads
    v.ready()
    settle(v)
    with pytest.raises(Unauthenticated) as refused:
        v.verify(fresh(clock[0], hop=b"retiring"), METHOD)
    assert refused.value.code == "stamp_proof"
    v.verify(fresh(clock[0], hop=b"current"), METHOD)


# Each key serves its own purpose only: an admission key published among the
# Work Context keys admits nothing, and an admission key never signs a Work
# Context.
def test_a_key_is_used_for_its_own_purpose_only():
    from authority_client.work_context import Trust
    response = publishing()
    response.keys.append(hop_key(b"misplaced"))
    v = Verifier(Keys(response), audience=FIXTURE["audience"], replay=Replay(), now=lambda: FIXTURE["now"])
    with pytest.raises(Unauthenticated) as refused:
        v.verify(fresh(FIXTURE["now"], hop=b"misplaced"), METHOD)
    assert refused.value.code == "keys_unavailable"  # no admission key is published at all
    assert "hop-misplaced" not in Trust.from_keys(response).keys


# An authority that publishes no admission key admits nothing, under a fixed
# reason, and says why in the module's logs.
def test_no_published_admission_key_refuses_every_call_and_says_why():
    from codefly_hop import NoAdmissionKeys
    v = Verifier(Keys(publishing()), audience=FIXTURE["audience"], replay=Replay(), now=lambda: FIXTURE["now"])
    with pytest.raises(Unauthenticated) as refused:
        v.verify(fresh(FIXTURE["now"]), METHOD)
    assert refused.value.code == "keys_unavailable"
    assert isinstance(v.keys_error, NoAdmissionKeys)


# Review r5: a verifier that first read the keys before the hop registered its
# key holds no admission key; once the authority publishes one, the next call
# or readiness check after KEY_RETRY reads it, without waiting out KEY_MAX_AGE,
# and callers inside KEY_RETRY drive no read.
def test_a_verifier_that_read_before_the_hop_registered_learns_its_key_within_key_retry():
    clock = [FIXTURE["now"]]
    source = Keys(publishing())
    v = Verifier(source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0])
    with pytest.raises(Unauthenticated) as refused:
        v.verify(fresh(clock[0], hop=b"the-hop"), METHOD)
    assert refused.value.code == "keys_unavailable"
    settle(v)
    reads = source.reads
    for _ in range(5):
        with pytest.raises(Unauthenticated):
            v.verify(fresh(clock[0], hop=b"the-hop"), METHOD)
    settle(v)
    assert source.reads == reads
    source.response = publishing(b"the-hop")
    clock[0] += KEY_RETRY
    assert v.verify(fresh(clock[0], hop=b"the-hop"), METHOD).owner == FIXTURE["identity"]["owner"]
    idle_source = Keys(publishing())
    idle = Verifier(idle_source, audience=FIXTURE["audience"], replay=Replay(), now=lambda: clock[0])
    idle.ready()
    settle(idle)
    idle_source.response = publishing(b"the-hop")
    clock[0] += KEY_RETRY
    idle.ready()
    settle(idle)
    assert idle.keys_error is None


# Review r3 M3: a store with reserve and no finish is not a reservation store
# (TypeScript's rule): it is consumed, so no reservation is left that nothing
# finishes.
class HalfReservations(Replay):
    def __init__(self):
        super().__init__()
        self.reserved = []
    def reserve(self, nonce, until):
        self.reserved.append(nonce)
    async def reserve_async(self, nonce, until):
        self.reserved.append(nonce)


def test_a_store_with_reserve_but_no_finish_is_consumed_not_reserved():
    import asyncio
    store = HalfReservations()
    v = Verifier(Keys(published()), audience=FIXTURE["audience"], replay=store, now=lambda: FIXTURE["now"])
    v.verify(fresh(FIXTURE["now"]), METHOD)
    asyncio.run(v.verify_async(fresh(FIXTURE["now"]), METHOD))
    assert not store.reserved and len(store.seen) == 2
