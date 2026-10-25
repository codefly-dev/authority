import json
from pathlib import Path

import pytest

from codefly_hop import (
    ADVISORY_KEY,
    CONTEXT_KEY,
    EXPIRES_KEY,
    PROOF_KEY,
    TENANT_KEY,
    WORK_CONTEXT_KEY,
    NoStamp,
    read,
)

FIXTURE = json.loads((Path(__file__).parents[2] / "testdata" / "stamped.json").read_text())


def stamped(**changes):
    headers = dict(FIXTURE["headers"])
    for key, value in changes.items():
        if value is None:
            headers.pop(key, None)
        else:
            headers[key] = value
    return headers


def test_the_stamp_the_hop_writes_reads_back_as_its_identity():
    identity = read(FIXTURE["headers"], FIXTURE["proof"])
    assert (identity.owner, identity.owner_kind, identity.tenant) == ("remi", "human", "acme")
    assert identity.actors == ("robin",)
    assert identity.binding == "acme/robin/model"
    assert (identity.task, identity.expires) == ("task-7", 1792818000)
    assert identity.context == FIXTURE["headers"][WORK_CONTEXT_KEY]
    assert identity.advisory == "documents.collection:read is not held"
    assert identity.has("modelservice.profiles", "invoke")
    assert not identity.has("modelservice.profiles", "admin")


def test_header_names_are_case_insensitive_and_repeats_are_kept():
    pairs = [(key.title(), value) for key, value in FIXTURE["headers"].items()]
    assert read(pairs, FIXTURE["proof"]).tenant == "acme"
    twice = pairs + [(WORK_CONTEXT_KEY, "another-token")]
    with pytest.raises(NoStamp):
        read(twice, FIXTURE["proof"])


@pytest.mark.parametrize(
    "headers,proof",
    [
        (stamped(), ""),  # no proof delivered: every call bypassed the hop
        (stamped(), "another-run"),  # another run's hop
        (stamped(**{PROOF_KEY: None}), "fixture-proof"),  # no stamp at all
        (stamped(**{TENANT_KEY: None}), "fixture-proof"),  # a stamp naming no tenant
        (stamped(**{WORK_CONTEXT_KEY: "swapped-after-the-check"}), "fixture-proof"),
        (stamped(**{CONTEXT_KEY: "0" * 64}), "fixture-proof"),
        (stamped(**{EXPIRES_KEY: "soon"}), "fixture-proof"),
    ],
)
def test_a_call_without_this_runs_stamp_acts_for_no_one(headers, proof):
    with pytest.raises(NoStamp):
        read(headers, proof)


def test_advisory_is_preserved_without_changing_scope_or_stamp_checks():
    reason = "documents.collection:read is not held"
    headers = stamped(**{ADVISORY_KEY: reason})
    identity = read(headers, FIXTURE["proof"])
    assert identity.advisory == reason
    assert not identity.has("documents.collection", "read")
    assert identity.context == FIXTURE["headers"][WORK_CONTEXT_KEY]
    assert read(stamped(**{ADVISORY_KEY: None}), FIXTURE["proof"]).advisory == ""
    with pytest.raises(NoStamp):
        read(headers, "wrong-proof")
