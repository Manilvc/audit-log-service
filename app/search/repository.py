"""Elasticsearch data access for audit events.

The only module that talks to the cluster about audit documents. Callers pass a
`TenantScope`; they never pass an index name, so a wrong-tenant read is not
expressible through this API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from elasticsearch import AsyncElasticsearch, NotFoundError

from app.core.logging import get_logger
from app.core.metrics import EVENTS_DUPLICATE
from app.search.query import (
    AuditSearchFilter,
    TenantScope,
    build_aggregation_body,
    build_search_body,
)
from app.search.routing import RouteDecision, TenantRouter

logger = get_logger(__name__)


@dataclass(slots=True)
class BulkOutcome:
    """Per-item result of a bulk write.

    Partial failure is the normal case worth designing for: 499 documents
    indexing and 1 being rejected by a mapping conflict must not be reported as
    total success (evidence silently lost) or total failure (498 duplicates on
    retry). Failed items are returned so the caller can route them to the
    dead-letter queue.
    """

    succeeded: int = 0
    failed: list[tuple[dict[str, Any], str]] = field(default_factory=list)
    took_ms: int = 0

    duplicates: int = 0
    """Items Elasticsearch rejected as 409 because the event id already exists.

    Counted separately from `succeeded` because it carries different meaning for
    the hash chain. A duplicate means this batch is a *redelivery*: the events are
    already durable under the sequence numbers assigned on the first attempt, so
    the sequence numbers just reserved for them are orphaned. Committing the chain
    head from an orphaned reservation would publish a head matching no stored
    document, and every later event would chain onto a phantom. The worker uses
    this to skip the commit and resync from the ledger instead.
    """

    duplicate_event_ids: list[str] = field(default_factory=list)
    """Event ids that came back 409, for the warning log."""

    @property
    def total(self) -> int:
        """Succeeded plus failed item count for this bulk request."""
        return self.succeeded + len(self.failed)

    @property
    def all_succeeded(self) -> bool:
        """True when every item was accepted (including ES 409 duplicates)."""
        return not self.failed


@dataclass(slots=True)
class SearchPage:
    """One page of results plus the cursor for the next."""

    events: list[dict[str, Any]]
    next_cursor: list[Any] | None
    total: int | None
    """None when total tracking was disabled, which is the default."""
    took_ms: int
    timed_out: bool


class AuditRepository:
    """Reads and writes audit documents."""

    def __init__(
        self,
        client: AsyncElasticsearch,
        router: TenantRouter,
        *,
        max_window_days: int,
        search_timeout: str,
    ) -> None:
        self._client = client
        self._router = router
        self._max_window_days = max_window_days
        self._search_timeout = search_timeout

    # ------------------------------------------------------------------ write
    async def bulk_index(self, items: list[tuple[RouteDecision, dict[str, Any]]]) -> BulkOutcome:
        """Index a batch of documents.

        Uses `op_type: create`, which is the only operation a data stream
        accepts - and the right one regardless, since an audit document must
        never overwrite an existing one. `_id` is set to the event id, so a
        replayed queue message is rejected as a duplicate rather than producing
        a second copy of the same event. That gives the whole ingest path
        exactly-once semantics on top of an at-least-once queue.
        """
        if not items:
            return BulkOutcome()

        operations: list[dict[str, Any]] = []
        for route, document in items:
            action: dict[str, Any] = {
                "create": {
                    "_index": route.write_target,
                    "_id": _event_id_of(document),
                }
            }
            if route.routing_key:
                action["create"]["routing"] = route.routing_key
            operations.append(action)
            operations.append(document)

        response = await self._client.bulk(
            operations=operations,
            # Wait for the write to be searchable? No - `refresh=False` keeps
            # ingest throughput high, and the 1s refresh interval means an
            # event is queryable well within any human timeframe.
            refresh=False,
        )

        outcome = BulkOutcome(took_ms=int(response.get("took", 0)))
        if not response.get("errors"):
            outcome.succeeded = len(items)
            return outcome

        for position, entry in enumerate(response.get("items", [])):
            result = entry.get("create", {})
            status = result.get("status", 500)
            if status < 300:
                outcome.succeeded += 1
                continue
            if status == 409:
                # Already stored: the exactly-once guarantee working. Counted as
                # a success for durability purposes, but ALSO tracked as a
                # duplicate, because it tells the worker this batch is a
                # redelivery and its reservation must not advance the chain.
                outcome.succeeded += 1
                outcome.duplicates += 1
                _, duplicate_document = items[position]
                duplicate_id = _event_id_of(duplicate_document)
                if duplicate_id:
                    outcome.duplicate_event_ids.append(duplicate_id)
                EVENTS_DUPLICATE.inc()
                continue
            error = result.get("error", {}) or {}
            # The type is what identifies the failure class
            # (strict_dynamic_mapping_exception, document_parsing_exception,
            # circuit_breaking_exception...). Elasticsearch puts it in `type`,
            # not in `reason`, and the retry/dead-letter decision in
            # `worker._is_permanent` matches on it - so it must be captured.
            error_type = str(error.get("type", "unknown"))
            reason = str(error.get("reason", "unknown error"))
            _, document = items[position]
            outcome.failed.append((document, f"status={status} type={error_type} {reason}"))

        if outcome.failed:
            logger.error(
                "bulk_index_partial_failure",
                failed=len(outcome.failed),
                succeeded=outcome.succeeded,
                first_reason=outcome.failed[0][1],
            )
        return outcome

    # ------------------------------------------------------------------- read
    async def search(
        self,
        scope: TenantScope,
        criteria: AuditSearchFilter,
        *,
        size: int,
        search_after: list[Any] | None = None,
        with_total: bool | int = False,
        source_fields: list[str] | None = None,
    ) -> SearchPage:
        """Run a tenant-scoped search."""
        targets, routing = self._resolve_read(scope)
        body = build_search_body(
            scope,
            criteria,
            size=size,
            max_window_days=self._max_window_days,
            search_after=search_after,
            track_total_hits=with_total,
            source_fields=source_fields,
            timeout=self._search_timeout,
        )

        response = await self._client.search(
            index=",".join(targets),
            body=body,
            routing=routing,
            # A tenant promoted to a dedicated stream has no stream yet until
            # its first event, so a missing index is expected rather than an error.
            ignore_unavailable=True,
            # Correctness over availability: a partial result set in a
            # compliance report is worse than an explicit failure, because the
            # reader cannot tell that records are missing.
            allow_partial_search_results=False,
            # Skips shards whose @timestamp range cannot match, which is the
            # single biggest win when querying a narrow window over years of
            # backing indices.
            pre_filter_shard_size=1,
        )
        return _to_page(response)

    async def aggregate(
        self,
        scope: TenantScope,
        criteria: AuditSearchFilter,
        *,
        group_by: str,
        interval: str | None = None,
        size: int = 50,
    ) -> dict[str, Any]:
        """Run a dashboard aggregation.

        `group_by` is validated against an allow-list by the caller
        (`services.query_service`); an arbitrary field name here would let a
        client aggregate on a high-cardinality field and exhaust heap.
        """
        targets, routing = self._resolve_read(scope)
        body = build_aggregation_body(
            scope,
            criteria,
            group_by=group_by,
            max_window_days=self._max_window_days,
            interval=interval,
            size=size,
        )
        response = await self._client.search(
            index=",".join(targets),
            body=body,
            routing=routing,
            ignore_unavailable=True,
            allow_partial_search_results=False,
            pre_filter_shard_size=1,
        )
        return dict(response.get("aggregations", {}))

    async def get_event(self, scope: TenantScope, event_id: str) -> dict[str, Any] | None:
        """Fetch one event by id, still tenant-filtered.

        Deliberately a search rather than a GET by document id: a GET would
        return the document regardless of tenant, making an id-guessing attack a
        cross-tenant read. The id is unique, so the cost difference is trivial.
        """
        targets, routing = self._resolve_read(scope)
        filters: list[dict[str, Any]] = [{"term": {"event.id": event_id}}]
        if not scope.cross_tenant:
            filters.append({"term": {"tenant.id": scope.tenant_id}})

        response = await self._client.search(
            index=",".join(targets),
            body={
                "query": {"bool": {"filter": filters}},
                "size": 1,
                "track_total_hits": False,
            },
            routing=routing,
            ignore_unavailable=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        return dict(hits[0]["_source"]) if hits else None

    # ------------------------------------------------- export / point in time
    async def open_pit(self, scope: TenantScope, *, keep_alive: str = "5m") -> str:
        """Open a point-in-time for a consistent export.

        Without a PIT, a long export paginating with `search_after` sees new
        documents arriving between pages, so the extract is a smear across time
        rather than a snapshot - unusable as evidence. A PIT freezes the view.
        """
        targets, _ = self._resolve_read(scope)
        response = await self._client.open_point_in_time(
            index=",".join(targets),
            keep_alive=keep_alive,
            ignore_unavailable=True,
        )
        return str(response["id"])

    async def search_pit(
        self,
        scope: TenantScope,
        criteria: AuditSearchFilter,
        *,
        pit_id: str,
        size: int,
        search_after: list[Any] | None = None,
        keep_alive: str = "5m",
    ) -> SearchPage:
        """Page through a PIT. The index is implied by the PIT, not passed."""
        body = build_search_body(
            scope,
            criteria,
            size=size,
            max_window_days=self._max_window_days,
            search_after=search_after,
            track_total_hits=False,
            timeout=self._search_timeout,
            # Ascending for exports: chronological order is what a reviewer
            # expects, and it matches hash-chain order for verification.
            ascending=True,
        )
        body["pit"] = {"id": pit_id, "keep_alive": keep_alive}
        response = await self._client.search(body=body)
        return _to_page(response)

    async def close_pit(self, pit_id: str) -> None:
        """Release a PIT. Safe to call twice.

        A leaked PIT pins Lucene segments and blocks disk reclamation, so this
        must run even on the error path - hence swallowing NotFoundError.
        """
        try:
            await self._client.close_point_in_time(id=pit_id)
        except NotFoundError:
            pass
        except Exception as exc:
            logger.warning("close_pit_failed", error=str(exc))

    # --------------------------------------------------------------- integrity
    async def fetch_chain_slice(
        self,
        *,
        chain_id: str,
        tenant_id: str,
        start_seq: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Fetch a contiguous chain slice in sequence order, for verification.

        Sorted by `integrity.seq` rather than `@timestamp`: the chain's order is
        its sequence, and two events can share a millisecond timestamp.
        """
        scope = TenantScope(tenant_id=tenant_id)
        targets, routing = self._resolve_read(scope)
        response = await self._client.search(
            index=",".join(targets),
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"tenant.id": tenant_id}},
                            {"term": {"integrity.chain_id": chain_id}},
                            {"range": {"integrity.seq": {"gte": start_seq}}},
                        ]
                    }
                },
                "size": limit,
                "sort": [{"integrity.seq": {"order": "asc"}}],
                "track_total_hits": False,
            },
            routing=routing,
            ignore_unavailable=True,
            allow_partial_search_results=False,
        )
        return [dict(hit["_source"]) for hit in response.get("hits", {}).get("hits", [])]

    async def count_by_key_id(self, *, tenant_id: str, key_id: str) -> int:
        """How many documents are protected by one PII key.

        Reported back on an erasure request so the DSR response can state how
        many records were affected - a documentation requirement under both
        GDPR Art. 19 and DPDP.
        """
        scope = TenantScope(tenant_id=tenant_id)
        targets, routing = self._resolve_read(scope)
        response = await self._client.count(
            index=",".join(targets),
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"tenant.id": tenant_id}},
                            {"term": {"pii.key_id": key_id}},
                        ]
                    }
                }
            },
            routing=routing,
            ignore_unavailable=True,
        )
        return int(response.get("count", 0))

    # ------------------------------------------------------------------ helpers
    def _resolve_read(self, scope: TenantScope) -> tuple[tuple[str, ...], str | None]:
        """Translate a scope into concrete read targets and a routing key."""
        if scope.cross_tenant:
            # No routing key: a cross-tenant read genuinely must fan out.
            return self._router.cross_tenant_read_targets(), None
        decision = self._router.resolve(scope.tenant_id)
        return decision.read_targets, decision.routing_key


def _to_page(response: Any) -> SearchPage:
    """Convert an Elasticsearch search reply into a page.

    Typed `Any` because the client returns `ObjectApiResponse`, which behaves
    like a mapping at runtime but is not declared as one in the stubs.
    """
    hits_block = response.get("hits", {})
    hits = hits_block.get("hits", [])
    total_block = hits_block.get("total")
    total = int(total_block["value"]) if isinstance(total_block, dict) else None

    return SearchPage(
        events=[dict(hit["_source"]) for hit in hits],
        # The cursor is the last hit's sort values; absent when the page was
        # not full, which is how the caller knows it has reached the end.
        next_cursor=list(hits[-1]["sort"]) if hits else None,
        total=total,
        took_ms=int(response.get("took", 0)),
        timed_out=bool(response.get("timed_out", False)),
    )


def _event_id_of(document: dict[str, Any]) -> str | None:
    event = document.get("event")
    if isinstance(event, dict):
        value = event.get("id")
        return str(value) if value else None
    return None
