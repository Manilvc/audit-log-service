"""Prometheus metrics for the audit ingest pipeline.

`/metrics` exposes these gauges and counters plus the process defaults from
``prometheus_client``. Names mirror the ops signals called out in the README
so dashboards and alerts stay aligned with the runbook.

Gauges (polled on ``GET /health``)
    ``audit_queue_total`` / ``audit_queue_dead_letter_total``
Counters (incremented on the hot path)
    ``audit_events_ingested_total`` — API accept vs reject
    ``audit_events_written_total`` — worker durable writes
    ``audit_events_dead_lettered_total`` / ``audit_events_duplicate_total``
    ``audit_chain_resynced_from_ledger_total`` — Redis cold → ES rebuild
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge

QUEUE_DEPTH = Gauge(
    "audit_queue_total",
    "Pending Redis Stream entries across all ingest partitions",
)

QUEUE_DEAD_LETTER_TOTAL = Gauge(
    "audit_queue_dead_letter_total",
    "Dead-lettered ingest entries across all partitions (never trimmed)",
)

EVENTS_INGESTED = Counter(
    "audit_events_ingested_total",
    "Events accepted by the API and enqueued",
    ["outcome"],
)

EVENTS_WRITTEN = Counter(
    "audit_events_written_total",
    "Events durably written by the worker (ES + archive path)",
)

EVENTS_DEAD_LETTERED = Counter(
    "audit_events_dead_lettered_total",
    "Events permanently rejected to the DLQ",
)

EVENTS_DUPLICATE = Counter(
    "audit_events_duplicate_total",
    "Events skipped because ES already held the event id (exactly-once)",
)

CHAIN_RESYNCED = Counter(
    "audit_chain_resynced_from_ledger_total",
    "Times a partition chain head was rebuilt from Elasticsearch",
)

ARCHIVE_SEAL_FAILED = Counter(
    "audit_archive_seal_failed_total",
    "Batches whose WORM segment write failed (batch left unacknowledged)",
)

EVENTS_UNARCHIVED = Counter(
    "audit_events_unarchived_total",
    "Events acknowledged as durable in ES with no WORM segment written. "
    "Any non-zero value is a compliance gap and must alert.",
)
