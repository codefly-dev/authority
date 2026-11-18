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
from codefly_hop import ADMITTED_KEY, Admission, Grant, Method, Permission, Unauthenticated, Verifier, admission_of, admitted, encode_grants, grants_of
from test_hop import Keys, Replay

STAMPS = json.loads((Path(__file__).parents[2] / "testdata/stamps.json").read_text())


def source(vector):
    """The authority's Keys as the vector publishes them, or one that cannot be read."""
    if vector["keys"] is None:
        return Keys(error=RuntimeError("dial authority.internal:4000: connection refused"))
    return Keys(json_format.ParseDict(vector["keys"], KeysResponse()))


def declarations(vector):
    """What the module hands its verifier: each method's declaration, or none."""
    if "declared" not in vector:
        return None
    pairs = lambda rows: tuple(Permission(kind, action) for kind, action in rows)
    return {method: Method(any_checked_caller=d["any_checked_caller"], requires=pairs(d["requires"]), carries=pairs(d["carries"]))
            for method, d in vector["declared"].items()}


def reading(admission, grants):
    """Every reading an Admission answers, in the vectors' shape: Go's
    admissionRead (libraries/hop/go/vectors_test.go), probed the same way."""
    owners = sorted({"", "another-owner", *(g.owner for g in grants)})
    ids = sorted({"", "another-id", *(i for g in grants for i in g.resources)})

    def read(selection, nested=False):
        out = {
            "empty": selection.empty(), "whole": selection.whole(), "owners": selection.owners(),
            "named": [{"owner": n.owner, "resources": list(n.resources)} for n in selection.named()],
            "allows": [{"owner": owner, "id": i, "allowed": selection.allows(owner, i)} for owner in owners for i in ids],
        }
        if not nested:
            out["owner_selected"] = read(selection.owner_selected(), True)
        return out

    # The owner-selected readings a handler writes are the vectors' own.
    assert read(admission.required_owner_selected(), True) == read(admission.required().owner_selected(), True)
    assert read(admission.carried_owner_selected(), True) == read(admission.carried().owner_selected(), True)
    return {
        "method": admission.method, "declared": admission.declared, "any_checked_caller": admission.any_checked_caller,
        "grants": [[g.kind, g.action, g.owner, list(g.resources)] for g in grants],
        "required": read(admission.required()), "carried": read(admission.carried()),
        "each": [{"kind": h.permission.kind, "action": h.permission.action, "carried": h.carried, "selection": read(h.selection)}
                 for h in admission.each()],
        "apart": admission.apart(),
    }


def deliveries(vector, mode):
    """Two deliveries of the vector's call, each to a verifier of its own on one
    shared store: the verdicts of the first and, when admitted, the second."""
    store = Replay()
    headers = [tuple(pair) for pair in vector["headers"]]

    def build():
        return Verifier(source(vector), audience=vector["audience"], replay=store, now=lambda: vector["now"],
                        declarations=declarations(vector))

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
    # What admitted the call: every reading Go hands a handler, or none at all
    # for a call the hop stamped no admission on.
    if "admission" not in vector:
        assert first.admitted is None, "an admission was invented for a call the hop stamped none on"
        nothing = admitted(first)
        assert not nothing.stamped and nothing.required().empty() and nothing.carried().empty() and nothing.each() == ()
        assert not nothing.required().allows("installation-a", "c-1") and nothing.required().owners() == []
        return
    assert first.admitted is not None and admitted(first) is first.admitted and first.admitted.stamped
    assert reading(first.admitted, first.grants) == vector["admission"]
    stamped = dict(vector["headers"])[ADMITTED_KEY]
    assert encode_grants(first.grants) == stamped and grants_of(stamped) == first.grants


def test_a_module_reads_its_own_narrowing_in_a_test_without_a_verifier():
    """Go's AdmissionOf: a test of a module's own narrowing builds an
    admission from a declaration and grants, given in any order and repeated."""
    declared = Method(requires=(Permission("records.records", "read"),), carries=(Permission("records.records", "read_content"),))
    grants = [Grant("records.records", "read_content", "installation-a", ("r-2", "r-1", "r-2")), Grant("records.records", "read", "installation-a"),
              Grant("records.records", "read", "installation-a"), Grant("records.records", "read", "installation-b")]
    read = admission_of(declared, "/records.v1.Records/Content", grants)
    assert isinstance(read, Admission) and read.declared and read.required().owners() == ["installation-a", "installation-b"]
    carried = read.carried()
    assert carried.owners() == [] and [(n.owner, n.resources) for n in carried.named()] == [("installation-a", ("r-1", "r-2"))]
    assert carried.allows("installation-a", "r-1") and not carried.allows("installation-a", "r-3") and not carried.allows("installation-b", "r-1")
    assert not carried.allows("installation-a", ""), "named resources never cover every resource of their owner"
    assert str(Permission("records.records", "read")) == "records.records:read"


def test_a_grant_that_selects_no_owner_lends_an_owner_selected_reading_nothing():
    """Go's TestRequiredIsWhereEveryRequiredPermissionIsHeld: a method that
    requires two permissions reaches an owner, owner-selected, only where both
    are held by a grant that selects that owner."""
    writes = Method(requires=(Permission("records.records", "read"), Permission("records.records", "write")))
    read = lambda owner, *ids: Grant("records.records", "read", owner, ids)
    write = lambda owner, *ids: Grant("records.records", "write", owner, ids)
    lent = admission_of(writes, "/records.v1.Records/Write", [read("installation-a"), write("")])
    assert lent.required().owners() == ["installation-a"] and not lent.required().whole()
    assert lent.required_owner_selected().empty() and lent.required().owner_selected().empty()
    assert not lent.required_owner_selected().allows("installation-a", "r-1")
    held = admission_of(writes, "/records.v1.Records/Write", [read("installation-a"), write(""), write("installation-a")])
    assert held.required_owner_selected().owners() == ["installation-a"]
    named = admission_of(writes, "/records.v1.Records/Write", [read("installation-a"), write("", "r-1"), write("installation-a", "r-2")])
    assert [(n.owner, n.resources) for n in named.required_owner_selected().named()] == [("installation-a", ("r-2",))]
    apart = admission_of(writes, "/records.v1.Records/Write", [read("installation-a"), write("installation-b")])
    assert apart.required().empty() and apart.required_owner_selected().empty()
    # Go's TestApartIsWhatTheHopRefusesAndReachesNothing: held on no owner in
    # common is what the hop refuses; a grant that selects no owner is held
    # together with anything, and only owners are compared.
    assert apart.apart() and not lent.apart() and not held.apart() and not named.apart()
    assert admission_of(writes, "/records.v1.Records/Write", [read("installation-a", "r-1"), write("installation-b", "r-1")]).apart()
    assert not admission_of(writes, "/records.v1.Records/Write", [read("installation-a", "r-1"), write("installation-a", "r-2")]).apart()
    assert not admission_of(writes, "/records.v1.Records/Write", [read("installation-a")]).apart()
    assert not admitted(None).apart()
    content = Method(requires=(Permission("records.records", "read"),), carries=(Permission("records.records", "read_content"),))
    carried = admission_of(content, "/records.v1.Records/Content", [read(""), Grant("records.records", "read_content", "installation-a")])
    assert carried.carried().owners() == ["installation-a"] and carried.carried_owner_selected().empty()


@pytest.mark.parametrize("value", ["", "W10=", "bm90IGpzb24", "WzFd", "W1siayIsImEiLCIiXV0", "W1siayIsImEiLCIiLFsxXV1d", "W1siayIsImEiLDEsW11dXQ", "e30"])
def test_a_malformed_admission_stamp_decodes_to_no_grants(value):
    with pytest.raises(ValueError):
        grants_of(value)
