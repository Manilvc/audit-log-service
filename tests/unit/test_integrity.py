"""Hash-chain tamper evidence.

Each test simulates one concrete attack against a stored audit trail and asserts
that verification not only fails, but reports *which* attack it was. The
distinction matters operationally: "a record was edited" and "a record was
deleted" call for different incident responses.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from app.core.integrity import (
    GENESIS_HASH,
    canonical_json,
    checkpoint_payload,
    compute_hash,
    hash_preimage,
    verify_chain,
)

CHAIN = "tenant-a:3"


def _doc(seq: int, action: str = "user.login") -> dict[str, Any]:
    """A minimal stored document, without its integrity block."""
    return {
        "@timestamp": f"2026-08-27T10:{seq:02d}:00+00:00",
        "event": {"id": f"evt-{seq}", "action": action, "outcome": "success"},
        "tenant": {"id": "tenant-a"},
        "actor": {"id": "u-1", "type": "user"},
    }


def _build_chain(length: int, chain_id: str = CHAIN) -> list[dict[str, Any]]:
    """A correctly chained run of documents, as the worker would produce."""
    documents: list[dict[str, Any]] = []
    prev = GENESIS_HASH
    for seq in range(length):
        document = _doc(seq)
        digest = compute_hash(chain_id, seq, prev, document)
        document["integrity"] = {
            "seq": seq,
            "prev_hash": prev,
            "hash": digest,
            "algo": "sha256",
            "chain_id": chain_id,
        }
        prev = digest
        documents.append(document)
    return documents


# ---------------------------------------------------------------------------
# Canonical serialisation
# ---------------------------------------------------------------------------
def test_canonical_json_is_key_order_independent() -> None:
    """The same logical document must hash identically regardless of key order.

    Elasticsearch may return `_source` keys in a different order than they were
    written, so a verifier re-canonicalises before comparing. Without this
    property every verification would fail.
    """
    left = {"b": 1, "a": {"d": 2, "c": 3}}
    right = {"a": {"c": 3, "d": 2}, "b": 1}
    assert canonical_json(left) == canonical_json(right)


def test_canonical_json_emits_no_insignificant_whitespace() -> None:
    assert canonical_json({"a": 1, "b": 2}) == b'{"a":1,"b":2}'


def test_hash_excludes_the_integrity_block() -> None:
    """A document cannot hash over its own hash."""
    document = _doc(0)
    without = compute_hash(CHAIN, 0, GENESIS_HASH, document)
    document["integrity"] = {"seq": 0, "hash": "anything", "prev_hash": GENESIS_HASH}
    with_block = compute_hash(CHAIN, 0, GENESIS_HASH, document)
    assert without == with_block


def test_preimage_is_length_prefixed_against_boundary_shifting() -> None:
    """Length framing prevents a boundary-shifting collision.

    With plain concatenation, chain "a" at seq 12 and chain "a1" at seq 2 would
    both produce "a12" and could share a preimage. Framing makes the components
    unambiguous.
    """
    left = hash_preimage("a", 12, GENESIS_HASH, {})
    right = hash_preimage("a1", 2, GENESIS_HASH, {})
    assert left != right
    assert compute_hash("a", 12, GENESIS_HASH, {}) != compute_hash("a1", 2, GENESIS_HASH, {})


def test_hash_binds_the_chain_id() -> None:
    """The same document in two chains gets different hashes.

    Otherwise a document could be lifted from one tenant's chain into another's
    and still verify.
    """
    document = _doc(0)
    assert compute_hash("tenant-a:0", 0, GENESIS_HASH, document) != compute_hash(
        "tenant-b:0", 0, GENESIS_HASH, document
    )


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------
def test_untampered_chain_verifies() -> None:
    result = verify_chain(CHAIN, _build_chain(20), expect_contiguous_from=0)
    assert result.intact
    assert result.verified_count == 20
    assert result.first_seq == 0
    assert result.last_seq == 19


def test_empty_slice_verifies_vacuously_rather_than_raising() -> None:
    """ "Nothing to check" must be distinguishable from "the check failed"."""
    result = verify_chain(CHAIN, [], expect_contiguous_from=0)
    assert result.intact
    assert result.verified_count == 0
    assert result.first_seq is None


# ---------------------------------------------------------------------------
# Attack: modification in place
# ---------------------------------------------------------------------------
def test_modified_field_is_detected_as_hash_mismatch() -> None:
    """Editing any field of a stored record breaks its hash."""
    documents = _build_chain(10)
    documents[4]["event"]["outcome"] = "failure"  # cover up a failed action

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert not result.intact
    kinds = {break_.kind for break_ in result.breaks}
    assert "hash_mismatch" in kinds
    mismatch = next(b for b in result.breaks if b.kind == "hash_mismatch")
    assert mismatch.seq == 4
    assert mismatch.event_id == "evt-4"


def test_a_single_tamper_does_not_cascade_into_every_later_record() -> None:
    """One edited document must not report breaks on all subsequent records.

    Verification continues from the *stored* hash rather than the recomputed
    one. Chaining from the recomputed value would flag every later document and
    bury the actual point of failure - useless during an incident.
    """
    documents = _build_chain(30)
    documents[10]["actor"]["id"] = "someone-else"

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert len(result.breaks) == 1
    assert result.breaks[0].seq == 10


def test_modifying_the_stored_hash_too_is_still_detected() -> None:
    """Recomputing the hash after editing does not help the attacker.

    The `prev_hash` of the next document still points at the original hash, so
    the link breaks even though the edited document is internally consistent.
    """
    documents = _build_chain(10)
    documents[5]["event"]["action"] = "user.logout"
    documents[5]["integrity"]["hash"] = compute_hash(
        CHAIN, 5, documents[5]["integrity"]["prev_hash"], documents[5]
    )

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert not result.intact
    assert any(break_.kind == "prev_mismatch" for break_ in result.breaks)


# ---------------------------------------------------------------------------
# Attack: deletion
# ---------------------------------------------------------------------------
def test_deleted_middle_record_is_detected_as_gap_and_broken_link() -> None:
    documents = _build_chain(10)
    del documents[5]

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert not result.intact
    kinds = {break_.kind for break_ in result.breaks}
    assert "gap" in kinds
    assert "prev_mismatch" in kinds


def test_deleted_prefix_is_detected_when_verifying_from_the_origin() -> None:
    """Truncating the start of a chain is detected - but only if asserted.

    Verifying a window starting at seq 500 cannot distinguish "the window
    starts here" from "0-499 were deleted", which is exactly why a full audit
    passes `expect_contiguous_from=0`.
    """
    documents = _build_chain(10)[3:]

    strict = verify_chain(
        CHAIN,
        documents,
        expected_start_hash=documents[0]["integrity"]["prev_hash"],
        expect_contiguous_from=0,
    )
    assert not strict.intact
    assert any(break_.kind == "gap" and "expected 0" in break_.detail for break_ in strict.breaks)

    # The same slice verifies as a mid-chain window, which is correct behaviour.
    windowed = verify_chain(
        CHAIN,
        documents,
        expected_start_hash=documents[0]["integrity"]["prev_hash"],
        expect_contiguous_from=None,
    )
    assert windowed.intact


def test_deleted_tail_is_caught_by_the_notarised_checkpoint_not_the_chain() -> None:
    """Truncating the end leaves a self-consistent chain.

    This is the limit of chaining alone, and precisely why chain heads are
    sealed into WORM storage: the shortened chain verifies, but its head no
    longer matches the immutable checkpoint.
    """
    full = _build_chain(10)
    checkpoint = checkpoint_payload(
        CHAIN,
        seq=9,
        head_hash=full[9]["integrity"]["hash"],
        sealed_at="2026-08-27T10:10:00+00:00",
        event_count=10,
    )

    truncated = full[:7]
    assert verify_chain(CHAIN, truncated, expect_contiguous_from=0).intact

    # The tamper only becomes visible against the notarised head.
    assert truncated[-1]["integrity"]["hash"] != checkpoint["head_hash"]
    assert checkpoint["seq"] > truncated[-1]["integrity"]["seq"]


# ---------------------------------------------------------------------------
# Attack: reordering, insertion, replay
# ---------------------------------------------------------------------------
def test_reordered_records_are_detected() -> None:
    documents = _build_chain(10)
    documents[3], documents[6] = documents[6], documents[3]

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert not result.intact
    assert any(break_.kind == "prev_mismatch" for break_ in result.breaks)


def test_inserted_forged_record_is_detected() -> None:
    """A forged record cannot be spliced in without breaking a link."""
    documents = _build_chain(10)
    forged = _doc(99, action="permission.grant")
    forged["integrity"] = {
        "seq": 5,
        "prev_hash": documents[4]["integrity"]["hash"],
        "hash": compute_hash(CHAIN, 5, documents[4]["integrity"]["hash"], forged),
        "algo": "sha256",
        "chain_id": CHAIN,
    }
    documents.insert(5, forged)

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert not result.intact
    kinds = {break_.kind for break_ in result.breaks}
    # The genuine seq 5 now duplicates the forged one, and its prev link no
    # longer matches.
    assert "duplicate_seq" in kinds or "prev_mismatch" in kinds


def test_replayed_duplicate_sequence_is_detected() -> None:
    documents = _build_chain(10)
    documents.insert(5, copy.deepcopy(documents[4]))

    result = verify_chain(CHAIN, documents, expect_contiguous_from=0)
    assert not result.intact
    assert any(break_.kind == "duplicate_seq" for break_ in result.breaks)


def test_document_without_integrity_block_raises() -> None:
    """A document this service never wrote cannot be reasoned about."""
    documents = _build_chain(3)
    del documents[1]["integrity"]
    with pytest.raises(ValueError, match="not produced by this service"):
        verify_chain(CHAIN, documents, expect_contiguous_from=0)


# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------
def test_checkpoint_carries_a_self_hash() -> None:
    """A doctored checkpoint is detectable too."""
    payload = checkpoint_payload(
        CHAIN,
        seq=100,
        head_hash="abc",
        sealed_at="2026-08-27T00:00:00+00:00",
        event_count=100,
    )
    original = payload.pop("self_hash")

    import hashlib

    assert original == hashlib.sha256(canonical_json(payload)).hexdigest()

    payload["seq"] = 50  # attacker rewinds the notarised position
    assert original != hashlib.sha256(canonical_json(payload)).hexdigest()
