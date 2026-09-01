"""Durable ingest buffer on Redis Streams.

Why a queue sits in front of Elasticsearch
-----------------------------------------
An audit event that is dropped is a compliance gap, and writing straight to the
cluster makes every ES hiccup - a rolling restart, a mapping error, a full disk -
into lost evidence. Redis Streams give an append-only log with consumer groups
and explicit acknowledgement, so an event is only removed once it is durably in
Elasticsearch *and* the WORM archive. If ES is down for an hour, the backlog
drains afterwards.

Redis needs `appendonly yes` with `appendfsync everysec` for this to be a real
durability guarantee; `docker-compose.yml` and the deployment notes set it. With
AOF off, Redis is a buffer, not a queue.

Partitioning
------------
One stream per partition, with a tenant pinned to a partition by a stable
digest. That is what lets the hash chain be per (tenant, partition): all of a
tenant's events flow through one ordered stream, so sequence numbers are
allocated in the order the events actually arrived.

Delivery semantics
------------------
At-least-once from the queue, exactly-once overall: the ES write uses
`op_type: create` with the event id as `_id`, so a redelivered message is
rejected as a duplicate rather than stored twice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import orjson
from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.core.logging import get_logger

logger = get_logger(__name__)

#: Field name inside the stream entry holding the serialised event.
_PAYLOAD_FIELD: Final[str] = "e"

#: Suffix for the dead-letter stream of a partition.
_DLQ_SUFFIX: Final[str] = "dlq"


@dataclass(frozen=True, slots=True)
class QueuedEvent:
    """A stream entry ready to be processed."""

    message_id: str
    partition: int
    payload: dict[str, Any]
    delivery_count: int


class IngestQueue:
    """Producer and consumer over the partitioned Redis Streams."""

    def __init__(
        self,
        redis: Redis,
        *,
        key_prefix: str,
        consumer_group: str,
        partitions: int,
        max_len: int,
    ) -> None:
        self._redis = redis
        self._prefix = key_prefix
        self._group = consumer_group
        self._partitions = partitions
        self._max_len = max_len

    # ------------------------------------------------------------------- keys
    def stream_key(self, partition: int) -> str:
        return f"{self._prefix}:{partition}"

    def dlq_key(self, partition: int) -> str:
        return f"{self._prefix}:{partition}:{_DLQ_SUFFIX}"

    @property
    def partitions(self) -> int:
        return self._partitions

    # --------------------------------------------------------------- producer
    async def publish(self, partition: int, payload: dict[str, Any]) -> str:
        """Append one event. Returns the stream message id.

        `maxlen` with `approximate=True` caps memory growth. This is a safety
        valve, not routine behaviour: hitting it means the workers have fallen so
        far behind that the oldest un-consumed events are being discarded, so it
        is alerted on as data loss. The cap is set high enough (a million
        entries by default) that only a sustained outage reaches it.
        """
        return str(
            await self._redis.xadd(
                self.stream_key(partition),
                {_PAYLOAD_FIELD: orjson.dumps(payload)},
                maxlen=self._max_len,
                approximate=True,
            )
        )

    async def publish_many(self, items: list[tuple[int, dict[str, Any]]]) -> list[str]:
        """Append a batch, pipelined into a single round trip.

        A 500-event batch would otherwise be 500 sequential RTTs, which
        dominates ingest latency far more than Redis itself.
        """
        if not items:
            return []
        pipe = self._redis.pipeline(transaction=False)
        for partition, payload in items:
            pipe.xadd(
                self.stream_key(partition),
                {_PAYLOAD_FIELD: orjson.dumps(payload)},
                maxlen=self._max_len,
                approximate=True,
            )
        return [str(result) for result in await pipe.execute()]

    # --------------------------------------------------------------- consumer
    async def ensure_groups(self) -> None:
        """Create the consumer group on every partition. Idempotent."""
        for partition in range(self._partitions):
            try:
                await self._redis.xgroup_create(
                    name=self.stream_key(partition),
                    groupname=self._group,
                    id="0",
                    mkstream=True,
                )
                logger.info("consumer_group_created", partition=partition)
            except ResponseError as exc:
                if "BUSYGROUP" not in str(exc):
                    raise

    async def read(
        self,
        *,
        consumer: str,
        partition: int,
        count: int,
        block_ms: int,
    ) -> list[QueuedEvent]:
        """Read undelivered entries for this consumer.

        `>` means "entries never delivered to this group". Entries already
        delivered but not acknowledged are recovered separately by
        `claim_stale`, so a crashed worker's in-flight batch is not stranded.
        """
        response = await self._redis.xreadgroup(
            groupname=self._group,
            consumername=consumer,
            streams={self.stream_key(partition): ">"},
            count=count,
            block=block_ms,
        )
        return _parse_stream_response(response, partition, delivery_count=1)

    async def claim_stale(
        self,
        *,
        consumer: str,
        partition: int,
        min_idle_ms: int,
        count: int,
    ) -> list[QueuedEvent]:
        """Take over entries a dead worker never acknowledged.

        Without this, a worker killed mid-batch would leave its events pending
        forever - present in Redis, absent from Elasticsearch, and invisible to
        monitoring that only watches queue depth.
        """
        try:
            claimed = await self._redis.xautoclaim(
                name=self.stream_key(partition),
                groupname=self._group,
                consumername=consumer,
                min_idle_time=min_idle_ms,
                count=count,
            )
        except ResponseError as exc:
            logger.warning("xautoclaim_failed", partition=partition, error=str(exc))
            return []

        # XAUTOCLAIM returns (next_cursor, entries, deleted) in Redis >= 7.
        entries = claimed[1] if len(claimed) > 1 else []
        events: list[QueuedEvent] = []
        for message_id, fields in entries:
            payload = _decode_payload(fields)
            if payload is None:
                continue
            events.append(
                QueuedEvent(
                    message_id=_as_str(message_id),
                    partition=partition,
                    payload=payload,
                    # Reclaimed at least once, so treat it as a retry. The exact
                    # count comes from XPENDING when a decision needs it.
                    delivery_count=2,
                )
            )
        if events:
            logger.warning("reclaimed_stale_events", partition=partition, count=len(events))
        return events

    async def ack(self, partition: int, message_ids: list[str]) -> None:
        """Acknowledge and delete processed entries.

        XACK then XDEL: acknowledging alone leaves the entry in the stream
        consuming memory forever, since nothing else trims a stream whose
        `maxlen` is far from being reached.
        """
        if not message_ids:
            return
        key = self.stream_key(partition)
        pipe = self._redis.pipeline(transaction=False)
        pipe.xack(key, self._group, *message_ids)
        pipe.xdel(key, *message_ids)
        await pipe.execute()

    async def to_dead_letter(
        self,
        partition: int,
        *,
        payload: dict[str, Any],
        reason: str,
        attempts: int,
    ) -> None:
        """Park an event that cannot be written.

        The DLQ is never trimmed. An audit event that failed permanently is
        exactly the thing an auditor will ask about, so it is retained until
        someone resolves it - deliberately unlike the main stream, which has a
        memory cap.
        """
        await self._redis.xadd(
            self.dlq_key(partition),
            {
                _PAYLOAD_FIELD: orjson.dumps(payload),
                "reason": reason[:1024],
                "attempts": str(attempts),
            },
        )
        logger.error(
            "event_dead_lettered",
            partition=partition,
            reason=reason,
            attempts=attempts,
            event_id=_extract_event_id(payload),
        )

    # ------------------------------------------------------------------ health
    async def depth(self) -> dict[str, int]:
        """Pending and total entry counts per partition, for the health probe.

        Rising depth is the earliest signal that ingest is degrading, well
        before anything user-visible breaks.
        """
        pipe = self._redis.pipeline(transaction=False)
        for partition in range(self._partitions):
            pipe.xlen(self.stream_key(partition))
            pipe.xlen(self.dlq_key(partition))
        results = await pipe.execute()

        depths: dict[str, int] = {}
        total = 0
        dlq_total = 0
        for partition in range(self._partitions):
            length = int(results[partition * 2] or 0)
            dlq_length = int(results[partition * 2 + 1] or 0)
            depths[f"partition_{partition}"] = length
            total += length
            dlq_total += dlq_length
        depths["total"] = total
        depths["dead_letter_total"] = dlq_total
        return depths

    async def pending_count(self, partition: int) -> int:
        """Entries delivered but not yet acknowledged on a partition."""
        # Explicitly Any: redis-py's XPENDING reply shape differs between the
        # summary and extended forms, and the stub only describes one of them.
        # Narrowing from Any keeps both runtime branches reachable.
        summary: Any
        try:
            summary = await self._redis.xpending(self.stream_key(partition), self._group)
        except ResponseError:
            return 0
        if isinstance(summary, dict):
            return int(summary.get("pending", 0))
        return int(summary[0]) if summary else 0


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------
def _parse_stream_response(
    response: Any,
    partition: int,
    *,
    delivery_count: int,
) -> list[QueuedEvent]:
    events: list[QueuedEvent] = []
    for _stream, entries in response or []:
        for message_id, fields in entries:
            payload = _decode_payload(fields)
            if payload is None:
                # Undecodable entry: nothing can be done with it, and leaving it
                # pending would block the partition forever.
                logger.error(
                    "undecodable_stream_entry",
                    partition=partition,
                    message_id=_as_str(message_id),
                )
                continue
            events.append(
                QueuedEvent(
                    message_id=_as_str(message_id),
                    partition=partition,
                    payload=payload,
                    delivery_count=delivery_count,
                )
            )
    return events


def _decode_payload(fields: Any) -> dict[str, Any] | None:
    raw = fields.get(_PAYLOAD_FIELD) or fields.get(_PAYLOAD_FIELD.encode())
    if raw is None:
        return None
    try:
        decoded = orjson.loads(raw)
    except orjson.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _as_str(value: Any) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


def _extract_event_id(payload: dict[str, Any]) -> str | None:
    value = payload.get("event_id")
    return str(value) if value else None
