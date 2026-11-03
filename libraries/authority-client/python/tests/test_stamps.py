"""The wire-level half of the hop conformance target, replayed by Python.

``testdata/stamps.json`` is written by the Go hop library's test
(``libraries/hop/go/vectors_test.go``): signed admissions on the wire, as the
hop forwards them, each with the verdict the contract names at a fixed clock.
This verifier must reach the same verdict, for the same reason, reading the
same identity, through both of its admission paths. The behavioural half of the
target is ``libraries/conformance/hop/go``.
"""

import asyncio
import json
from pathlib import Path

import pytest
from google.protobuf import json_format

from authority_client._gen.host.authority.v1.authority_pb2 import KeysResponse
from codefly_hop import Unauthenticated, Verifier
from test_hop import Keys, Replay

STAMPS = json.loads((Path(__file__).parents[2] / "testdata/stamps.json").read_text())


def source(vector):
    """The authority's Keys as the vector publishes them, or one that cannot be read."""
    if vector["keys"] is None:
        return Keys(error=RuntimeError("dial authority.internal:4000: connection refused"))
    return Keys(json_format.ParseDict(vector["keys"], KeysResponse()))


def deliveries(vector, mode):
    """Two deliveries of the vector's call, each to a verifier of its own on one
    shared store: the verdicts of the first and, when admitted, the second."""
    store = Replay()
    headers = [tuple(pair) for pair in vector["headers"]]

    def build():
        return Verifier(source(vector), audience=vector["audience"], replay=store, now=lambda: vector["now"])

    def deliver(verifier):
        try:
            if mode == "async":
                return asyncio.run(verifier.verify_async(headers, vector["method"]))
            return verifier.verify(headers, vector["method"])
        except Unauthenticated as refused:
            return refused

    first = deliver(build())
    second = deliver(build()) if not isinstance(first, Unauthenticated) else None
    return first, second


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("vector", STAMPS, ids=lambda v: v["name"])
def test_python_reaches_gos_verdict_on_every_stamp_vector(vector, mode):
    first, second = deliveries(vector, mode)
    if not vector["accept"]:
        assert isinstance(first, Unauthenticated), f"admitted; the contract refuses as {vector['reason']}"
        assert first.code == vector["reason"]
        for _, value in vector["headers"]:
            assert len(value) <= 16 or value not in str(first), "the refusal names the call's metadata"
        return
    assert not isinstance(first, Unauthenticated), f"refused as {getattr(first, 'code', None)}; the contract admits"
    want = vector["identity"]
    assert (first.owner, first.owner_kind, first.tenant, first.binding, first.task, first.expires) == (
        want["owner"], want["owner_kind"], want["tenant"], want["binding"], want["task"], want["expires"])
    assert list(first.actors) == want["actors"] and list(first.scopes) == want["scopes"]
    assert first.advisory == ""
    assert first.context == dict(vector["headers"])["x-codefly-work-context"]
    assert isinstance(second, Unauthenticated) and second.code == vector["replay"]
