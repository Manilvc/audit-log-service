"""Ingest worker: queue -> hash chain -> Elasticsearch -> WORM archive.

Runs as a separate process (`audit-service worker`) so ingest throughput scales
independently of the API, and a slow archive write never adds latency to an
emitting service's request.

Single writer per partition
---------------------------
Sequence *reservation* is atomic, but hash *chaining* is not: two workers that
both reserve from the same uncommitted head would each chain onto that head, and
the second block's `prev_hash` would skip the first block entirely. Atomicity
alone therefore is not enough - a partition must have exactly one active writer.

That is enforced with a Redis lease per partition, at three levels, because the
lease expiring while a worker is mid-batch is a real and observed occurrence:

1. **Acquire** - `SET NX EX` means only one worker enters a partition.
2. **Stop on loss** - the renewer signals an `asyncio.Event` when a renewal
   fails, and the drain loop checks it every iteration. Without this the loop
   ran forever once entered, so a worker whose lease had lapsed kept writing
   alongside the new owner.
3. **Refuse the commit** - `ChainAllocator.commit` re-checks lease ownership
   inside the same Lua script that moves the head, so even a batch that began
   while the lease was valid cannot publish a head after losing it. The batch is
   left unacknowledged for the new owner instead.

Levels 2 and 3 exist because a divergent chain is indistinguishable from
tampering: an operator investigating a `prev_mismatch` cannot tell a lease race
from an attacker. The only acceptable behaviour is to not produce one.

Write ordering, and why a retry cannot corrupt the chain
-------------------------------------------------------
    reserve -> hash -> Elasticsearch -> WORM archive -> commit head -> ack

Nothing is acknowledged until the events are in both stores, so a crash means
redelivery, never loss. Redelivery is safe because the ES write is
`op_type: create` keyed on the event id, so a duplicate is rejected.

The subtle case is a crash *between* the ES write and the head commit. On retry
the events get fresh sequence numbers, but ES already holds them under their
original ones and answers 409. Committing the new head would then publish a head
that matches no stored document, and every later event would chain onto a
phantom. So any 409 in the batch means the reservation is untrustworthy: the head
is *not* committed and the chain is resynced from Elasticsearch, which is the
authoritative ledger. The orphaned reservation leaves a gap, which is recorded
as a documented gap rather than silently papered over.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis

from app.core.config import Settings
from app.core.integrity import compute_hash
from app.core.logging import get_logger
from app.core.metrics import (
    EVENTS_DEAD_LETTERED,
    EVENTS_DUPLICATE,
    EVENTS_WRITTEN,
)
from app.core.security.crypto import KeyRingError, PiiCipher
from app.domain.events import AuditEvent
from app.queue.chain import ChainAllocator
from app.queue.stream import IngestQueue, QueuedEvent
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter

logger = get_logger(__name__)

#: How long a partition lease is held before it must be renewed. Long enough to
#: survive a slow batch, short enough that a dead worker's partition is picked
#: up promptly.
_LEASE_TTL_SECONDS = 30
_LEASE_RENEW_SECONDS = 10

#: `ChainAllocator.commit` result codes.
_COMMIT_LEASE_LOST = -1
_COMMIT_STALE = 0
_COMMIT_OK = 1

#: An entry pending this long is assumed to belong to a dead worker.
_STALE_AFTER_MS = 60_000

#: Only release a lease we still own - otherwise a worker whose lease already
#: expired and was taken over would delete the new owner's lease.
_RELEASE_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"""

_RENEW_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return 0
"""


@dataclass(slots=True)
class BatchStats:
    """Per-batch counters, emitted as one structured log line."""

    read: int = 0
    written: int = 0
    dead_lettered: int = 0
    duplicates: int = 0
    chains_touched: set[str] = field(default_factory=set)


class IngestWorker:
    """Drains the ingest queue into the durable stores."""

    def __init__(
        self,
        *,
        settings: Settings,
        redis: Redis,
        queue: IngestQueue,
        chains: ChainAllocator,
        repository: AuditRepository,
        router: TenantRouter,
        cipher: PiiCipher,
        archive: Any,
        consumer_name: str | None = None,
    ) -> None:
        self._settings = settings
        self._redis = redis
        self._queue = queue
        self._chains = chains
        self._repository = repository
        self._router = router
        self._cipher = cipher
        self._archive = archive
        self._consumer = consumer_name or f"worker-{uuid.uuid4().hex[:8]}"
        self._stopping = asyncio.Event()
        self._release = redis.register_script(_RELEASE_LUA)
        self._renew = redis.register_script(_RENEW_LUA)
        # Events archived but not yet checkpointed, per chain. A checkpoint
        # every batch would be a tiny S3 object per batch; batching keeps the
        # notarisation rate sane without weakening the guarantee much.
        self._since_checkpoint: dict[str, int] = {}

    # ------------------------------------------------------------------ run
    async def run(self) -> None:
        """Process every partition concurrently until stopped."""
        await self._queue.ensure_groups()
        logger.info(
            "worker_starting",
            consumer=self._consumer,
            partitions=self._queue.partitions,
        )
        tasks = [
            asyncio.create_task(self._run_partition(partition), name=f"partition-{partition}")
            for partition in range(self._queue.partitions)
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            # Let cancellation actually land so leases are released before the
            # process exits, rather than waiting out their TTL.
            await asyncio.gather(*tasks, return_exceptions=True)

    def stop(self) -> None:
        """Ask the worker to finish the current batch and exit."""
        self._stopping.set()

    async def _run_partition(self, partition: int) -> None:
        """Own one partition for as long as its lease can be held."""
        lease_key = f"{self._settings.STREAM_KEY_PREFIX}:lease:{partition}"
        token = f"{self._consumer}:{uuid.uuid4().hex}"

        while not self._stopping.is_set():
            acquired = await self._redis.set(lease_key, token, nx=True, ex=_LEASE_TTL_SECONDS)
            if not acquired:
                # Another worker owns it. Back off rather than spin - the lease
                # TTL bounds how long a genuinely dead owner blocks us.
                await self._sleep(_LEASE_RENEW_SECONDS)
                continue

            # Signalled by the renewer when the lease is no longer ours. The
            # drain loop must stop promptly: continuing to write after another
            # worker has taken the partition is what breaks a hash chain.
            lease_lost = asyncio.Event()
            renewer = asyncio.create_task(self._renew_lease(lease_key, token, lease_lost))
            try:
                await self._drain_partition(partition, lease_key, token, lease_lost)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("partition_loop_failed", partition=partition)
                await self._sleep(2)
            finally:
                renewer.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await renewer
                await self._release(keys=[lease_key], args=[token])

    async def _renew_lease(self, lease_key: str, token: str, lease_lost: asyncio.Event) -> None:
        """Keep the partition lease alive; signal loudly if it lapses."""
        while True:
            await asyncio.sleep(_LEASE_RENEW_SECONDS)
            try:
                renewed = await self._renew(keys=[lease_key], args=[token, _LEASE_TTL_SECONDS])
            except Exception as exc:
                # A Redis blip is indistinguishable from a lost lease here, and
                # the safe reading is "lost": another worker may already own the
                # partition, so this one must stop writing.
                logger.error("lease_renew_failed", lease_key=lease_key, error=str(exc))
                lease_lost.set()
                return
            if not int(renewed):
                # Lost the lease (a long GC pause, a network partition, a clock
                # stall). Stop the drain loop rather than merely stopping
                # renewal - two writers on one partition corrupt the chain.
                logger.warning("partition_lease_lost", lease_key=lease_key)
                lease_lost.set()
                return

    async def _drain_partition(
        self,
        partition: int,
        lease_key: str,
        lease_token: str,
        lease_lost: asyncio.Event,
    ) -> None:
        """Read and process batches for as long as the lease is genuinely held.

        The `lease_lost` check is the load-bearing part. This loop previously
        ran forever once entered, so a worker whose lease lapsed kept writing
        while the new owner also wrote - both reserving from the same
        uncommitted head and producing divergent `prev_hash` values. A
        divergent chain is indistinguishable from tampering, so stopping here
        is a correctness requirement, not an optimisation.
        """
        while not self._stopping.is_set() and not lease_lost.is_set():
            # Reclaim first: a crashed worker's in-flight events are the oldest
            # and most at risk of breaching an ingest SLA.
            events = await self._queue.claim_stale(
                consumer=self._consumer,
                partition=partition,
                min_idle_ms=_STALE_AFTER_MS,
                count=self._settings.WORKER_BATCH_SIZE,
            )
            if not events:
                events = await self._queue.read(
                    consumer=self._consumer,
                    partition=partition,
                    count=self._settings.WORKER_BATCH_SIZE,
                    block_ms=self._settings.WORKER_BLOCK_MS,
                )
            if not events:
                continue

            stats = await self._process_batch(
                partition, events, lease_key=lease_key, lease_token=lease_token
            )
            if stats.written:
                EVENTS_WRITTEN.inc(stats.written)
            if stats.dead_lettered:
                EVENTS_DEAD_LETTERED.inc(stats.dead_lettered)
            if stats.duplicates:
                EVENTS_DUPLICATE.inc(stats.duplicates)
            logger.info(
                "batch_processed",
                partition=partition,
                read=stats.read,
                written=stats.written,
                dead_lettered=stats.dead_lettered,
                duplicates=stats.duplicates,
                chains=len(stats.chains_touched),
            )

    # -------------------------------------------------------------- processing
    async def _process_batch(
        self,
        partition: int,
        events: list[QueuedEvent],
        *,
        lease_key: str = "",
        lease_token: str = "",
    ) -> BatchStats:
        """Turn one batch of queued payloads into durable audit records."""
        stats = BatchStats(read=len(events))

        # Group by tenant: the hash chain is per (tenant, partition), so each
        # tenant's events must be sequenced as one contiguous block.
        by_tenant: dict[str, list[QueuedEvent]] = {}
        for queued in events:
            tenant_id = str(queued.payload.get("tenant_id") or "")
            if not tenant_id:
                await self._queue.to_dead_letter(
                    partition,
                    payload=queued.payload,
                    reason="missing tenant_id",
                    attempts=queued.delivery_count,
                )
                await self._queue.ack(partition, [queued.message_id])
                stats.dead_lettered += 1
                continue
            by_tenant.setdefault(tenant_id, []).append(queued)

        for tenant_id, group in by_tenant.items():
            await self._process_tenant_group(
                partition,
                tenant_id,
                group,
                stats,
                lease_key=lease_key,
                lease_token=lease_token,
            )
        return stats

    async def _process_tenant_group(
        self,
        partition: int,
        tenant_id: str,
        group: list[QueuedEvent],
        stats: BatchStats,
        *,
        lease_key: str = "",
        lease_token: str = "",
    ) -> None:
        chain_id = self._router.chain_id(tenant_id, partition)
        stats.chains_touched.add(chain_id)

        # ---- 1. validate + encrypt ------------------------------------------
        prepared: list[tuple[QueuedEvent, dict[str, Any]]] = []
        for queued in group:
            try:
                document = await self._prepare_document(tenant_id, queued.payload)
            except KeyRingError as exc:
                # Encrypting without a persisted key would create a permanently
                # unreadable record, so retry rather than store it.
                logger.error("keyring_unavailable", error=str(exc), tenant_id=tenant_id)
                return
            except Exception as exc:
                await self._queue.to_dead_letter(
                    partition,
                    payload=queued.payload,
                    reason=f"invalid event: {exc}",
                    attempts=queued.delivery_count,
                )
                await self._queue.ack(partition, [queued.message_id])
                stats.dead_lettered += 1
                continue
            prepared.append((queued, document))

        if not prepared:
            return

        # ---- 2. reserve chain positions -------------------------------------
        reservation = await self._chains.reserve(chain_id, len(prepared))
        prev_hash = reservation.prev_hash
        if reservation.was_cold:
            # Redis had no state. Distinguish a brand-new chain from a lost
            # Redis dataset by consulting the authoritative ledger; getting this
            # wrong would restart sequencing at 0 and look like forgery.
            recovered = await self._chains.resync_from_ledger(
                chain_id, tenant_id=tenant_id, ledger=self._repository
            )
            if recovered is not None:
                logger.warning(
                    "chain_cold_start_recovered",
                    chain_id=chain_id,
                    ledger_seq=recovered[0],
                )
                # Re-reserve from the corrected state.
                reservation = await self._chains.reserve(chain_id, len(prepared))
                prev_hash = reservation.prev_hash

        # ---- 3. chain and stamp ---------------------------------------------
        documents: list[dict[str, Any]] = []
        for offset, (_queued, document) in enumerate(prepared):
            seq = reservation.start_seq + offset
            digest = compute_hash(chain_id, seq, prev_hash, document)
            document["integrity"] = {
                "seq": seq,
                "prev_hash": prev_hash,
                "hash": digest,
                "algo": "sha256",
                "chain_id": chain_id,
            }
            prev_hash = digest
            documents.append(document)

        route = self._router.resolve(tenant_id)

        # ---- 4. Elasticsearch -----------------------------------------------
        outcome = await self._repository.bulk_index([(route, doc) for doc in documents])
        if not outcome.all_succeeded:
            # Do not ack: the queue redelivers. Do not commit the head either -
            # a partially-written block must not advance the chain.
            for document, reason in outcome.failed:
                logger.error("es_write_rejected", reason=reason)
                if _is_permanent(reason):
                    # A mapping conflict fails identically forever, so retrying
                    # only delays the alert. Park it for a human instead.
                    await self._queue.to_dead_letter(
                        partition,
                        payload=document,
                        reason=reason,
                        attempts=self._settings.WORKER_MAX_DELIVERY_ATTEMPTS,
                    )
                    stats.dead_lettered += 1
            return

        # ---- 4b. redelivery: the reservation is orphaned ---------------------
        if outcome.duplicates:
            # Elasticsearch already holds these events under the sequence numbers
            # assigned on an earlier attempt, so the numbers just reserved are
            # orphaned. Three things must NOT happen here:
            #
            #  * Do not commit the head. It would publish a hash matching no
            #    stored document, and every later event would chain onto a
            #    phantom - the chain silently breaks from this point on.
            #  * Do not seal an archive segment. It would notarise documents
            #    whose sequence numbers disagree with the stored ones, and
            #    Object Lock means that wrong record can never be removed.
            #  * Do not leave the batch unacknowledged. The events are already
            #    durable; redelivering forever cannot improve that and only
            #    burns another reservation each time.
            #
            # Instead: resync the chain from Elasticsearch, which is the
            # authoritative ledger, and acknowledge. The orphaned range becomes a
            # gap that `verify` reports and this log line explains.
            await self._chains.resync_from_ledger(
                chain_id, tenant_id=tenant_id, ledger=self._repository, force=True
            )
            await self._queue.ack(partition, [q.message_id for q, _ in prepared])
            stats.duplicates += outcome.duplicates
            logger.warning(
                "batch_was_redelivery_chain_resynced",
                chain_id=chain_id,
                duplicates=outcome.duplicates,
                orphaned_seq_range=f"{reservation.start_seq}-{reservation.last_seq}",
                event_ids=outcome.duplicate_event_ids[:10],
                detail=(
                    "events were already durable from an earlier attempt; the "
                    "chain head was NOT advanced and has been rebuilt from "
                    "Elasticsearch. The orphaned sequence range will show as a "
                    "documented gap."
                ),
            )
            return

        # ---- 5. WORM archive ------------------------------------------------
        if self._archive is not None and getattr(self._archive, "enabled", False):
            try:
                await self._archive.seal_segment(
                    tenant_id=tenant_id, chain_id=chain_id, documents=documents
                )
            except Exception as exc:
                # Un-notarised evidence is not acceptable, so leave the batch
                # unacknowledged and retry. ES already holds the documents and
                # will answer 409 next time, which triggers the resync path -
                # correct, if noisy.
                logger.error("archive_seal_failed", error=str(exc), chain_id=chain_id)
                return

        # ---- 6. commit head, then ack ---------------------------------------
        committed = await self._chains.commit(
            chain_id,
            last_seq=reservation.last_seq,
            head_hash=prev_hash,
            lease_key=lease_key or None,
            lease_token=lease_token or None,
        )
        if committed == _COMMIT_LEASE_LOST:
            # Another worker owns this partition now. Do NOT acknowledge: the
            # events are already in Elasticsearch, so redelivery hits the
            # duplicate path and reconciles the chain from the ledger.
            # Advancing the head from here would race the new owner.
            logger.error(
                "commit_refused_lease_lost",
                chain_id=chain_id,
                partition=partition,
                detail=(
                    "the partition lease lapsed mid-batch; the head was not "
                    "advanced and the batch was left for the new owner"
                ),
            )
            return
        if committed == _COMMIT_STALE:
            logger.warning("chain_head_commit_stale", chain_id=chain_id)

        await self._queue.ack(partition, [queued.message_id for queued, _ in prepared])
        stats.written += len(documents)

        await self._maybe_checkpoint(
            tenant_id=tenant_id,
            chain_id=chain_id,
            seq=reservation.last_seq,
            head_hash=prev_hash,
            added=len(documents),
        )

    async def _prepare_document(self, tenant_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Validate the payload and encrypt its PII.

        Validation happens here as well as at the API boundary: an event may
        have been queued by an older build, and a malformed document must be
        caught before it can poison a chain.
        """
        event = AuditEvent.model_validate(payload)
        event.ingested_at = event.ingested_at or datetime.now(UTC)
        document = event.to_document()

        subject_id = _subject_of(event)
        result = await self._cipher.encrypt_document(
            document,
            tenant_id=tenant_id,
            event_id=event.event_id,
            subject_id=subject_id,
        )
        if result.key_id:
            document["pii"] = {
                "encrypted": True,
                "key_id": result.key_id,
                "kek_version": self._settings.PII_KEK_VERSION,
                "fields": list(result.encrypted_paths),
                "shredded": False,
            }
        return result.document

    async def _maybe_checkpoint(
        self,
        *,
        tenant_id: str,
        chain_id: str,
        seq: int,
        head_hash: str,
        added: int,
    ) -> None:
        """Seal a notarised checkpoint once enough events have accumulated."""
        if self._archive is None or not getattr(self._archive, "enabled", False):
            return
        pending = self._since_checkpoint.get(chain_id, 0) + added
        if pending < self._settings.ARCHIVE_SEGMENT_MAX_EVENTS:
            self._since_checkpoint[chain_id] = pending
            return
        try:
            await self._archive.seal_checkpoint(
                tenant_id=tenant_id,
                chain_id=chain_id,
                seq=seq,
                head_hash=head_hash,
                event_count=pending,
            )
            self._since_checkpoint[chain_id] = 0
        except Exception as exc:
            # A missed checkpoint weakens notarisation but loses no data, so it
            # must not fail the batch that has already been acknowledged.
            logger.error("checkpoint_failed", chain_id=chain_id, error=str(exc))

    async def _sleep(self, seconds: float) -> None:
        """Sleep, but wake immediately on shutdown."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)


def _subject_of(event: AuditEvent) -> str | None:
    """Identify whose personal data this event carries.

    The actor is the subject in the overwhelming majority of events. Falling back
    to the target covers the case where an admin acts *on* someone - there the
    personal data in the record belongs to the target, and a DSR from the target
    must reach it.
    """
    if event.actor.id:
        return event.actor.id
    if event.target.id:
        return event.target.id
    return None


def _is_permanent(reason: str) -> bool:
    """Whether an Elasticsearch rejection is worth retrying.

    A mapping conflict or a malformed document will fail identically forever, so
    retrying only delays the alert. Anything else - circuit breakers, unavailable
    shards, timeouts - is transient and must be retried, because dropping it
    would lose evidence.
    """
    permanent_markers = (
        # An undeclared field: rejected identically forever.
        "strict_dynamic_mapping_exception",
        "mapper_parsing_exception",
        "illegal_argument_exception",
        # Covers the constant_keyword rejection a dedicated stream raises when a
        # document carries the wrong tenant id - a routing bug, not a blip, and
        # retrying it would spin forever.
        "document_parsing_exception",
        "status=400",
    )
    lowered = reason.lower()
    return any(marker in lowered for marker in permanent_markers)
