"""Tamper-evidence primitives: canonical serialisation and hash chaining.

Pure functions only - no I/O, no globals. That makes the integrity rules
independently testable and means a verifier can re-derive a hash from an
archived document years later without booting the service.

The scheme
----------
Every document joins a chain identified by `<tenant_id>:<partition>`. For
sequence *n*:

    hash_n = SHA256( chain_id || seq_n || prev_hash || canonical_json(doc_n) )

`doc_n` excludes the `integrity` block itself (it cannot contain its own hash)
but includes everything else, **after** PII encryption. Three attacks are
therefore detectable:

* **Mutation** - recomputed hash no longer matches the stored one.
* **Deletion** - a gap appears in `seq`, and the next document's `prev_hash`
  points at a hash nobody holds.
* **Reordering / insertion** - the `prev_hash` links break.

What this does *not* defend against is an attacker who controls both the store
and the chain head and rewrites the whole tail. That is what the periodic
checkpoint sealed into S3 Object Lock (`archive.s3_worm`) closes: the checkpoint
is immutable even to the account root, so a rewritten tail contradicts a
notarised hash.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Final

import orjson

HASH_ALGO: Final[str] = "sha256"

#: Chain head value for the first document in a chain. A fixed, well-known
#: constant (rather than random) so a verifier needs no side channel to start.
GENESIS_HASH: Final[str] = "0" * 64

#: Excluded from the hash preimage: a document cannot hash over its own hash.
_EXCLUDED_TOP_LEVEL: Final[frozenset[str]] = frozenset({"integrity"})


def canonical_json(document: dict[str, Any]) -> bytes:
    """Deterministically serialise a document for hashing.

    Determinism is the whole point: the same logical document must produce
    identical bytes on every machine, in every Python version, forever.
    `OPT_SORT_KEYS` sorts recursively, and orjson emits no insignificant
    whitespace and always UTF-8, so the output is stable.

    Note the asymmetry with what Elasticsearch stores: ES may reorder `_source`
    keys, so a verifier must re-canonicalise before comparing rather than
    hashing the raw bytes it received.
    """
    return orjson.dumps(document, option=orjson.OPT_SORT_KEYS)


def hash_preimage(chain_id: str, seq: int, prev_hash: str, document: dict[str, Any]) -> bytes:
    """Build the exact byte string that gets hashed.

    Length-prefixing each component prevents a boundary-shifting forgery: with
    plain concatenation, a crafted `chain_id` could absorb the `seq` digits and
    two different (chain, seq) pairs could share a preimage.
    """
    body = canonical_json(
        {key: value for key, value in document.items() if key not in _EXCLUDED_TOP_LEVEL}
    )
    parts = (chain_id.encode(), str(seq).encode(), prev_hash.encode(), body)
    framed = b"".join(len(part).to_bytes(8, "big") + part for part in parts)
    return framed


def compute_hash(chain_id: str, seq: int, prev_hash: str, document: dict[str, Any]) -> str:
    """Return the hex SHA-256 link for one document."""
    return hashlib.sha256(hash_preimage(chain_id, seq, prev_hash, document)).hexdigest()


def hashes_equal(left: str, right: str) -> bool:
    """Constant-time hash comparison.

    Hashes are public, so this is belt-and-braces rather than strictly needed -
    but the verify endpoint is reachable by callers who can also submit
    documents, and a timing oracle on hash comparison is a known way to
    incrementally forge a match.
    """
    return hmac.compare_digest(left, right)


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """A single detected discontinuity."""

    seq: int
    event_id: str | None
    kind: str
    """One of: gap, hash_mismatch, prev_mismatch, duplicate_seq."""
    detail: str


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of verifying a contiguous slice of a chain."""

    chain_id: str
    verified_count: int
    first_seq: int | None
    last_seq: int | None
    breaks: tuple[ChainBreak, ...]

    @property
    def intact(self) -> bool:
        """True when the verified slice has no discontinuities."""
        return not self.breaks


def verify_chain(
    chain_id: str,
    documents: list[dict[str, Any]],
    *,
    expected_start_hash: str = GENESIS_HASH,
    expect_contiguous_from: int | None = None,
) -> VerificationResult:
    """Verify a slice of one chain, ordered ascending by `integrity.seq`.

    Args:
        chain_id: The chain these documents claim to belong to.
        documents: Stored documents, each including its `integrity` block.
        expected_start_hash: `prev_hash` the first document must declare. Use
            `GENESIS_HASH` when verifying from the beginning of a chain, or the
            hash of the document preceding the slice otherwise.
        expect_contiguous_from: When given, require the slice to start at this
            sequence number. Verifying a mid-chain window without it cannot
            distinguish "the window starts at 500" from "sequences 0-499 were
            deleted", so a full-chain audit must always pass it.

    Returns:
        A `VerificationResult`. An empty document list verifies vacuously and
        is reported with `verified_count=0` rather than raising, so callers can
        distinguish "nothing to check" from "check failed".

    Raises:
        ValueError: A document is missing its `integrity` block, i.e. it was
            never written by this service and cannot be reasoned about.
    """
    breaks: list[ChainBreak] = []
    prev_hash = expected_start_hash
    prev_seq: int | None = None
    first_seq: int | None = None
    last_seq: int | None = None

    for index, document in enumerate(documents):
        integrity = document.get("integrity")
        if not isinstance(integrity, dict):
            raise ValueError(
                f"document at position {index} has no integrity block; "
                "it was not produced by this service"
            )

        seq = int(integrity["seq"])
        stored_hash = str(integrity["hash"])
        stored_prev = str(integrity["prev_hash"])
        event_id = _event_id_of(document)

        if first_seq is None:
            first_seq = seq
            if expect_contiguous_from is not None and seq != expect_contiguous_from:
                breaks.append(
                    ChainBreak(
                        seq=seq,
                        event_id=event_id,
                        kind="gap",
                        detail=(
                            f"chain starts at seq {seq}, expected "
                            f"{expect_contiguous_from}: earlier records are missing"
                        ),
                    )
                )
        elif prev_seq is not None:
            if seq == prev_seq:
                breaks.append(
                    ChainBreak(
                        seq=seq,
                        event_id=event_id,
                        kind="duplicate_seq",
                        detail=f"sequence {seq} appears more than once",
                    )
                )
            elif seq != prev_seq + 1:
                breaks.append(
                    ChainBreak(
                        seq=seq,
                        event_id=event_id,
                        kind="gap",
                        detail=f"sequence jumped from {prev_seq} to {seq}",
                    )
                )

        if not hashes_equal(stored_prev, prev_hash):
            breaks.append(
                ChainBreak(
                    seq=seq,
                    event_id=event_id,
                    kind="prev_mismatch",
                    detail=(
                        f"prev_hash {stored_prev[:16]}... does not match the "
                        f"preceding link {prev_hash[:16]}..."
                    ),
                )
            )

        recomputed = compute_hash(chain_id, seq, stored_prev, document)
        if not hashes_equal(recomputed, stored_hash):
            breaks.append(
                ChainBreak(
                    seq=seq,
                    event_id=event_id,
                    kind="hash_mismatch",
                    detail=(
                        f"recomputed {recomputed[:16]}... != stored "
                        f"{stored_hash[:16]}...: this document was modified"
                    ),
                )
            )

        # Continue from the *stored* hash. Chaining from the recomputed value
        # would let one tampered document cascade into a mismatch on every
        # later record and bury the real point of failure.
        prev_hash = stored_hash
        prev_seq = seq
        last_seq = seq

    return VerificationResult(
        chain_id=chain_id,
        verified_count=len(documents),
        first_seq=first_seq,
        last_seq=last_seq,
        breaks=tuple(breaks),
    )


def _event_id_of(document: dict[str, Any]) -> str | None:
    event = document.get("event")
    if isinstance(event, dict):
        value = event.get("id")
        return str(value) if value is not None else None
    return None


def checkpoint_payload(
    chain_id: str,
    *,
    seq: int,
    head_hash: str,
    sealed_at: str,
    event_count: int,
) -> dict[str, Any]:
    """Build the notarisation record sealed into the WORM archive.

    Small on purpose - it exists so an auditor can pin the chain head at a
    known time without trusting the mutable store. `self_hash` covers the
    checkpoint's own fields, so a doctored checkpoint is detectable too.
    """
    body = {
        "chain_id": chain_id,
        "seq": seq,
        "head_hash": head_hash,
        "sealed_at": sealed_at,
        "event_count": event_count,
        "algo": HASH_ALGO,
        "version": 1,
    }
    body["self_hash"] = hashlib.sha256(canonical_json(body)).hexdigest()
    return body
