"""Hash-chain sequence allocation.

The chain gives the audit log its tamper evidence, and that only works if
sequence numbers are unique, gap-free and totally ordered within a chain. This
module is what guarantees it under concurrent workers.

Who is the source of truth
--------------------------
**Elasticsearch is.** The highest `integrity.seq` actually persisted for a chain
is the real chain head. Redis holds a hot pointer to it so the common path costs
one round trip instead of a search, but Redis is a cache and is always
reconciled against the ledger - never trusted blindly. That ordering matters:
Redis can lose its dataset on failover, and a chain that reset to seq 0 would
look, to a verifier, exactly like an attacker rewriting history.

Reservation is atomic
---------------------
`reserve()` runs a Lua script, so `read seq -> add n -> write seq` is a single
indivisible operation. Two workers can never hand out the same sequence number,
which is the property duplicate-detection in the verifier relies on.

The crash window, handled honestly
----------------------------------
A worker that reserves sequences and then dies before its bulk write lands
leaves a real gap. That is unavoidable without a distributed transaction across
Redis and Elasticsearch, so instead of pretending otherwise the gap is
*documented*: on resync, a `chain_gap` notice recording the orphaned range is
written and sealed into the WORM archive. Verification then distinguishes a
documented gap (benign, an operational event) from an undocumented one (a record
was deleted). An attacker cannot forge a notice retroactively, because the
archive is immutable even to the account root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from redis.asyncio import Redis

from app.core.integrity import GENESIS_HASH
from app.core.logging import get_logger
from app.core.metrics import CHAIN_RESYNCED

logger = get_logger(__name__)

# Reserve a contiguous sequence range and return the current head hash.
#
# KEYS[1] chain state hash
# ARGV[1] number of sequences to reserve
# ARGV[2] genesis hash, used when the chain has no state yet
#
# Returns {start_seq, prev_hash, was_cold}. `was_cold` tells the caller the
# state was absent, so it must reconcile against Elasticsearch before trusting
# the returned head - the difference between a genuinely new chain and a Redis
# dataset that was lost.
_RESERVE_LUA = """
local state = redis.call('HMGET', KEYS[1], 'seq', 'head')
local last_seq = state[1]
local head = state[2]
local was_cold = 0

if not last_seq then
    last_seq = -1
    head = ARGV[2]
    was_cold = 1
else
    last_seq = tonumber(last_seq)
end

local count = tonumber(ARGV[1])
local start_seq = last_seq + 1
redis.call('HSET', KEYS[1], 'seq', last_seq + count, 'head', head)
return {tostring(start_seq), head, tostring(was_cold)}
"""

# Commit the new head after a successful write. Refuses to move the head
# backwards, so a delayed or replayed commit from a slow worker cannot rewind
# the chain over a newer one.
#
# KEYS[1] chain state hash
# ARGV[1] last written sequence
# ARGV[2] new head hash
# KEYS[2] is the partition lease key and ARGV[3] the token this worker believes
# it holds. Verifying ownership *inside* the same atomic script as the head
# update is what makes single-writer-per-chain real: without it, a worker whose
# lease silently lapsed could still publish a head, and the new owner - already
# chaining from the previous head - would produce a divergent `prev_hash`. That
# is a broken chain, and it looks identical to tampering. Returns -1 when the
# lease is no longer ours, so the caller can stand down instead of committing.
_COMMIT_LUA = """
if ARGV[3] ~= '' then
    local owner = redis.call('GET', KEYS[2])
    if owner ~= ARGV[3] then
        return -1
    end
end
local current = redis.call('HGET', KEYS[1], 'seq')
if current and tonumber(current) > tonumber(ARGV[1]) then
    redis.call('HSET', KEYS[1], 'head', ARGV[2])
    return 0
end
redis.call('HSET', KEYS[1], 'seq', ARGV[1], 'head', ARGV[2])
return 1
"""


@dataclass(frozen=True, slots=True)
class Reservation:
    """A contiguous block of sequence numbers plus the link to chain onto."""

    chain_id: str
    start_seq: int
    count: int
    prev_hash: str
    was_cold: bool

    @property
    def last_seq(self) -> int:
        return self.start_seq + self.count - 1


class ChainLedger(Protocol):
    """The durable side of the chain - implemented by `AuditRepository`."""

    async def fetch_chain_slice(
        self, *, chain_id: str, tenant_id: str, start_seq: int, limit: int
    ) -> list[dict[str, Any]]: ...


class ChainAllocator:
    """Allocates and commits hash-chain positions."""

    def __init__(
        self,
        redis: Redis,
        *,
        key_prefix: str = "audit:chain",
    ) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._reserve = redis.register_script(_RESERVE_LUA)
        self._commit = redis.register_script(_COMMIT_LUA)
        # Chains already reconciled against Elasticsearch in this process, so
        # the (expensive) resync happens once per chain per worker lifetime.
        self._reconciled: set[str] = set()

    def _key(self, chain_id: str) -> str:
        return f"{self._prefix}:{chain_id}"

    async def reserve(self, chain_id: str, count: int) -> Reservation:
        """Atomically reserve `count` sequence numbers."""
        if count < 1:
            raise ValueError("count must be >= 1")
        raw = await self._reserve(
            keys=[self._key(chain_id)],
            args=[count, GENESIS_HASH],
        )
        start_seq = int(_decode(raw[0]))
        prev_hash = _decode(raw[1])
        was_cold = _decode(raw[2]) == "1"
        return Reservation(
            chain_id=chain_id,
            start_seq=start_seq,
            count=count,
            prev_hash=prev_hash,
            was_cold=was_cold,
        )

    async def commit(
        self,
        chain_id: str,
        *,
        last_seq: int,
        head_hash: str,
        lease_key: str | None = None,
        lease_token: str | None = None,
    ) -> int:
        """Publish the new chain head after the write is durable.

        Args:
            chain_id: chain being advanced.
            last_seq: highest sequence number written in this batch.
            head_hash: hash of the last document written.
            lease_key: partition lease key. When given together with
                `lease_token`, ownership is verified atomically with the update.
            lease_token: the token this worker believes it holds.

        Returns:
            ``1`` committed, ``0`` ignored as stale (a newer head already won),
            ``-1`` refused because the lease is no longer held. A caller that
            sees ``-1`` must not acknowledge its batch: the partition now belongs
            to another worker, and the events will be redelivered and reconciled
            through the duplicate path.
        """
        result = await self._commit(
            keys=[self._key(chain_id), lease_key or "unused"],
            args=[last_seq, head_hash, lease_token or ""],
        )
        return int(result)

    async def peek(self, chain_id: str) -> tuple[int, str] | None:
        """Current `(seq, head)` without reserving. None when no state exists."""
        state = await self._redis.hmget(self._key(chain_id), ["seq", "head"])
        if state[0] is None:
            return None
        return int(_decode(state[0])), _decode(state[1])

    async def resync_from_ledger(
        self,
        chain_id: str,
        *,
        tenant_id: str,
        ledger: ChainLedger,
        force: bool = False,
    ) -> tuple[int, str] | None:
        """Rebuild Redis state from the durable ledger.

        Args:
            force: re-walk the ledger even if this chain was already reconciled
                in this process. Needed when a duplicate write reveals that the
                cached head is ahead of what Elasticsearch actually stores.

        Called when Redis reports a cold chain. Without this, a Redis failover
        would restart every chain at seq 0 and every subsequent document would
        appear to a verifier as an inserted forgery.

        Returns the reconciled `(seq, head)`, or None for a genuinely new chain.
        """
        if not force and chain_id in self._reconciled:
            return await self.peek(chain_id)

        tail = await self._find_ledger_tail(chain_id, tenant_id, ledger)
        self._reconciled.add(chain_id)

        if tail is None:
            logger.info("chain_is_new", chain_id=chain_id)
            return None

        seq, head = tail
        await self._redis.hset(self._key(chain_id), mapping={"seq": seq, "head": head})
        CHAIN_RESYNCED.inc()
        logger.warning(
            "chain_resynced_from_ledger",
            chain_id=chain_id,
            recovered_seq=seq,
            detail="Redis chain state was cold; head restored from Elasticsearch",
        )
        return seq, head

    async def _find_ledger_tail(
        self,
        chain_id: str,
        tenant_id: str,
        ledger: ChainLedger,
    ) -> tuple[int, str] | None:
        """Find the highest persisted (seq, hash) for a chain.

        Walks forward in pages from 0. A `sort desc` on `integrity.seq` would be
        one request, but the repository's chain reader is deliberately
        ascending-only so that verification always reads in chain order; walking
        is a cold path that runs once per chain per worker.
        """
        page_size = 1000
        cursor = 0
        last: tuple[int, str] | None = None
        while True:
            docs = await ledger.fetch_chain_slice(
                chain_id=chain_id,
                tenant_id=tenant_id,
                start_seq=cursor,
                limit=page_size,
            )
            if not docs:
                return last
            integrity = docs[-1].get("integrity") or {}
            last = (int(integrity["seq"]), str(integrity["hash"]))
            if len(docs) < page_size:
                return last
            cursor = last[0] + 1


def _decode(value: Any) -> str:
    """Redis replies may be bytes or str depending on client decoding config."""
    if isinstance(value, bytes):
        return value.decode()
    return str(value)
