"""Hash-chain sequence allocation under concurrency.

Two properties are load-bearing:

1. **Reservation is atomic.** Two workers must never receive the same sequence
   number, or the verifier reports permanent duplicate-seq breaks.
2. **A cold Redis is distinguishable from a new chain.** Redis can lose its
   dataset on failover. If the allocator restarted sequencing at 0, every
   subsequent document would look, to a verifier, exactly like an attacker
   inserting forged records.
"""

from __future__ import annotations

import asyncio
from typing import Any

import fakeredis.aioredis as fakeredis
import pytest

from app.core.integrity import GENESIS_HASH
from app.queue.chain import ChainAllocator

CHAIN = "tenant-a:3"


@pytest.fixture
async def redis() -> Any:
    client = fakeredis.FakeRedis(decode_responses=False)
    yield client
    await client.aclose()


@pytest.fixture
def allocator(redis: Any) -> ChainAllocator:
    return ChainAllocator(redis)


class FakeLedger:
    """Stands in for Elasticsearch as the authoritative chain ledger."""

    def __init__(self, documents: list[dict[str, Any]] | None = None) -> None:
        self.documents = documents or []
        self.calls = 0

    async def fetch_chain_slice(
        self, *, chain_id: str, tenant_id: str, start_seq: int, limit: int
    ) -> list[dict[str, Any]]:
        self.calls += 1
        matching = [
            document
            for document in self.documents
            if document["integrity"]["chain_id"] == chain_id
            and document["integrity"]["seq"] >= start_seq
        ]
        matching.sort(key=lambda document: document["integrity"]["seq"])
        return matching[:limit]


def _ledger_doc(seq: int, chain_id: str = CHAIN) -> dict[str, Any]:
    return {
        "integrity": {
            "seq": seq,
            "hash": f"hash-{seq}",
            "prev_hash": f"hash-{seq - 1}" if seq else GENESIS_HASH,
            "chain_id": chain_id,
        }
    }


# ---------------------------------------------------------------------------
# Basic allocation
# ---------------------------------------------------------------------------
async def test_first_reservation_starts_at_genesis(allocator: ChainAllocator) -> None:
    reservation = await allocator.reserve(CHAIN, 5)
    assert reservation.start_seq == 0
    assert reservation.last_seq == 4
    assert reservation.prev_hash == GENESIS_HASH
    # Flagged as cold so the caller knows to reconcile against the ledger.
    assert reservation.was_cold is True


async def test_reservations_do_not_overlap(allocator: ChainAllocator) -> None:
    first = await allocator.reserve(CHAIN, 10)
    second = await allocator.reserve(CHAIN, 5)
    assert first.last_seq == 9
    assert second.start_seq == 10
    assert second.last_seq == 14


async def test_commit_publishes_the_new_head(allocator: ChainAllocator) -> None:
    reservation = await allocator.reserve(CHAIN, 3)
    assert await allocator.commit(CHAIN, last_seq=reservation.last_seq, head_hash="h2") == 1

    following = await allocator.reserve(CHAIN, 1)
    assert following.start_seq == 3
    assert following.prev_hash == "h2"
    assert following.was_cold is False


async def test_chains_are_independent(allocator: ChainAllocator) -> None:
    """A tenant's sequencing must not be affected by another tenant's volume."""
    await allocator.reserve("tenant-a:0", 100)
    other = await allocator.reserve("tenant-b:0", 1)
    assert other.start_seq == 0


async def test_reserve_rejects_a_non_positive_count(
    allocator: ChainAllocator,
) -> None:
    with pytest.raises(ValueError, match="count must be >= 1"):
        await allocator.reserve(CHAIN, 0)


# ---------------------------------------------------------------------------
# Atomicity
# ---------------------------------------------------------------------------
async def test_concurrent_reservations_never_overlap(
    allocator: ChainAllocator,
) -> None:
    """The property duplicate-detection depends on.

    Fifty concurrent reservations of ten sequences each must partition 0..499
    exactly - no gaps, no overlaps. A non-atomic read-modify-write would produce
    both.
    """
    reservations = await asyncio.gather(*(allocator.reserve(CHAIN, 10) for _ in range(50)))
    allocated: list[int] = []
    for reservation in reservations:
        allocated.extend(range(reservation.start_seq, reservation.last_seq + 1))

    assert len(allocated) == 500
    assert len(set(allocated)) == 500, "sequence numbers were handed out twice"
    assert sorted(allocated) == list(range(500)), "the allocation left a gap"


async def test_commit_refuses_to_rewind_the_chain(
    allocator: ChainAllocator,
) -> None:
    """A delayed commit from a slow worker must not rewind a newer head.

    Rewinding would hand the next writer a stale `prev_hash`, breaking the chain
    for every document after it.
    """
    await allocator.reserve(CHAIN, 10)  # seq 0..9
    await allocator.commit(CHAIN, last_seq=9, head_hash="head-9")
    await allocator.reserve(CHAIN, 10)  # seq 10..19
    await allocator.commit(CHAIN, last_seq=19, head_hash="head-19")

    # A straggler tries to commit an older position. `commit` returns a result
    # code (1 committed / 0 stale / -1 lease lost) rather than a bool, so the
    # stale case is an explicit 0.
    accepted = await allocator.commit(CHAIN, last_seq=9, head_hash="head-9-late")
    assert accepted == 0

    state = await allocator.peek(CHAIN)
    assert state is not None
    assert state[0] == 19, "the sequence counter was rewound"


# ---------------------------------------------------------------------------
# Cold-start reconciliation
# ---------------------------------------------------------------------------
async def test_cold_chain_is_rebuilt_from_the_ledger(
    allocator: ChainAllocator,
) -> None:
    """A Redis failover must not restart sequencing at 0.

    This is the scenario that would otherwise make every later record look like
    a forgery to a verifier.
    """
    ledger = FakeLedger([_ledger_doc(seq) for seq in range(42)])

    recovered = await allocator.resync_from_ledger(CHAIN, tenant_id="tenant-a", ledger=ledger)
    assert recovered == (41, "hash-41")

    reservation = await allocator.reserve(CHAIN, 1)
    assert reservation.start_seq == 42
    assert reservation.prev_hash == "hash-41"


async def test_genuinely_new_chain_resyncs_to_nothing(
    allocator: ChainAllocator,
) -> None:
    """An empty ledger means a new chain, not a lost one."""
    recovered = await allocator.resync_from_ledger(
        CHAIN, tenant_id="tenant-a", ledger=FakeLedger([])
    )
    assert recovered is None
    assert (await allocator.reserve(CHAIN, 1)).start_seq == 0


async def test_resync_is_performed_once_per_chain_per_process(
    allocator: ChainAllocator,
) -> None:
    """The ledger walk is a cold path and must not run on every batch."""
    ledger = FakeLedger([_ledger_doc(seq) for seq in range(5)])
    await allocator.resync_from_ledger(CHAIN, tenant_id="tenant-a", ledger=ledger)
    calls_after_first = ledger.calls

    await allocator.resync_from_ledger(CHAIN, tenant_id="tenant-a", ledger=ledger)
    assert ledger.calls == calls_after_first


async def test_resync_walks_past_the_first_page(
    allocator: ChainAllocator,
) -> None:
    """A chain longer than one page must be walked to its true tail.

    Stopping at the first page would under-report the head and cause duplicate
    sequence numbers.
    """
    ledger = FakeLedger([_ledger_doc(seq) for seq in range(2500)])
    recovered = await allocator.resync_from_ledger(CHAIN, tenant_id="tenant-a", ledger=ledger)
    assert recovered == (2499, "hash-2499")


async def test_peek_reports_nothing_for_an_unknown_chain(
    allocator: ChainAllocator,
) -> None:
    assert await allocator.peek("tenant-z:0") is None


# ---------------------------------------------------------------------------
# Redelivery must not corrupt the chain
# ---------------------------------------------------------------------------
async def test_forced_resync_rewalks_an_already_reconciled_chain(
    allocator: ChainAllocator,
) -> None:
    """`force=True` re-reads the ledger even after a prior reconciliation.

    This is what the worker needs when a 409 reveals that the cached head is
    ahead of what Elasticsearch actually stores: without `force`, the memo would
    return the stale cached value and the chain would stay broken.
    """
    ledger = FakeLedger([_ledger_doc(seq) for seq in range(3)])
    first = await allocator.resync_from_ledger(CHAIN, tenant_id="tenant-a", ledger=ledger)
    assert first == (2, "hash-2")
    calls_after_first = ledger.calls

    # More events have since landed in the ledger.
    ledger.documents = [_ledger_doc(seq) for seq in range(8)]

    # Without force, the memo short-circuits and the stale head is returned.
    memoised = await allocator.resync_from_ledger(CHAIN, tenant_id="tenant-a", ledger=ledger)
    assert ledger.calls == calls_after_first
    assert memoised == (2, "hash-2")

    # With force, the ledger is re-walked and the true tail is adopted.
    forced = await allocator.resync_from_ledger(
        CHAIN, tenant_id="tenant-a", ledger=ledger, force=True
    )
    assert ledger.calls > calls_after_first
    assert forced == (7, "hash-7")

    # Subsequent reservations continue from the corrected head.
    reservation = await allocator.reserve(CHAIN, 1)
    assert reservation.start_seq == 8
    assert reservation.prev_hash == "hash-7"


async def test_head_is_not_advanced_when_a_reservation_is_orphaned(
    allocator: ChainAllocator,
) -> None:
    """An uncommitted reservation must leave the head where it was.

    This is the invariant the worker's redelivery branch depends on: reserving
    sequence numbers advances the counter, but only `commit` moves the hash. If
    reserving also moved the head, a batch that failed between the ES write and
    the commit would corrupt the chain for every later event.
    """
    await allocator.reserve(CHAIN, 2)
    await allocator.commit(CHAIN, last_seq=1, head_hash="head-1")

    # A batch reserves, then dies before committing.
    orphaned = await allocator.reserve(CHAIN, 2)
    assert orphaned.start_seq == 2
    assert orphaned.prev_hash == "head-1"

    state = await allocator.peek(CHAIN)
    assert state is not None
    # Counter advanced (so the numbers are never reused)...
    assert state[0] == 3
    # ...but the head did not move, because nothing was committed.
    assert state[1] == "head-1"


# ---------------------------------------------------------------------------
# Lease-guarded commit: the single-writer guarantee
# ---------------------------------------------------------------------------
LEASE_KEY = "audit:stream:lease:3"

COMMIT_OK = 1
COMMIT_STALE = 0
COMMIT_LEASE_LOST = -1


async def test_commit_succeeds_while_the_lease_is_held(
    allocator: ChainAllocator, redis: Any
) -> None:
    await redis.set(LEASE_KEY, b"worker-a:token1")
    await allocator.reserve(CHAIN, 2)

    result = await allocator.commit(
        CHAIN,
        last_seq=1,
        head_hash="head-1",
        lease_key=LEASE_KEY,
        lease_token="worker-a:token1",
    )
    assert result == COMMIT_OK
    state = await allocator.peek(CHAIN)
    assert state is not None
    assert state[1] == "head-1"


async def test_commit_is_refused_when_the_lease_was_taken_over(
    allocator: ChainAllocator, redis: Any
) -> None:
    """The core single-writer guarantee.

    A worker whose lease lapsed mid-batch must not publish a chain head: the new
    owner is already chaining from the previous head, and two heads for one
    position is a divergent chain - indistinguishable from tampering to anyone
    reading the verification report later.
    """
    await redis.set(LEASE_KEY, b"worker-a:token1")
    await allocator.reserve(CHAIN, 2)
    await allocator.commit(
        CHAIN,
        last_seq=1,
        head_hash="head-1",
        lease_key=LEASE_KEY,
        lease_token="worker-a:token1",
    )

    # Worker B takes over the partition (A's lease expired and B acquired it).
    await redis.set(LEASE_KEY, b"worker-b:token2")

    # A's in-flight batch now tries to commit.
    refused = await allocator.commit(
        CHAIN,
        last_seq=3,
        head_hash="head-3-from-stale-worker",
        lease_key=LEASE_KEY,
        lease_token="worker-a:token1",
    )
    assert refused == COMMIT_LEASE_LOST

    # The head is untouched, so worker B's chaining stays correct.
    state = await allocator.peek(CHAIN)
    assert state is not None
    assert state[1] == "head-1"


async def test_commit_is_refused_when_the_lease_expired_entirely(
    allocator: ChainAllocator, redis: Any
) -> None:
    """A missing lease key is a lost lease, not an open door."""
    await allocator.reserve(CHAIN, 1)
    refused = await allocator.commit(
        CHAIN,
        last_seq=0,
        head_hash="head-0",
        lease_key=LEASE_KEY,
        lease_token="worker-a:token1",
    )
    assert refused == COMMIT_LEASE_LOST


async def test_commit_without_lease_args_skips_the_ownership_check(
    allocator: ChainAllocator,
) -> None:
    """Back-compatible for callers with no lease (the CLI and tests)."""
    await allocator.reserve(CHAIN, 1)
    assert await allocator.commit(CHAIN, last_seq=0, head_hash="h0") == COMMIT_OK
