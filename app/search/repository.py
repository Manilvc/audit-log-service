"""Search-store data access for audit events.

The only module that talks to the store about audit documents. Callers pass a
`UserScope`; they never pass an index name, so a wrong-user read is not
expressible through this API.

Engine-agnostic: every call goes through `SearchBackend`, and the query bodies
are plain DSL that Elasticsearch and OpenSearch both accept. Nothing here names
an engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.core.metrics import EVENTS_DUPLICATE
from app.search.backends import SearchBackend, SearchNotFound
from app.search.query import (
    AuditSearchFilter,
    UserScope,
    build_aggregation_body,
    build_search_body,
)
from app.search.routing import RouteDecision, UserRouter

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
        backend: SearchBackend,
        router: UserRouter,
        *,
        max_window_days: int,
        search_timeout: str,
        default_window_days: int = 1,
    ) -> None:
        self._store = backend
        self._router = router
        self._max_window_days = max_window_days
        # Applied when the caller names neither bound. Clamped to the maximum,
        # so a misconfiguration cannot widen the ceiling the max is there to
        # enforce.
        self._default_window_days = max(1, min(default_window_days, max_window_days))
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

        outcome = BulkOutcome()
        operations: list[dict[str, Any]] = []
        writable: list[tuple[RouteDecision, dict[str, Any]]] = []
        for route, document in items:
            mismatch = _user_uuid_mismatch(document, route)
            if mismatch is not None:
                # Refused before it reaches the store. On a dedicated stream
                # Elasticsearch would reject this itself via `constant_keyword`,
                # but OpenSearch has no equivalent and the shared stream has no
                # such guard on either engine - so the invariant is enforced
                # here, where every write passes, rather than left to whichever
                # engine happens to be configured.
                logger.error(
                    "bulk_index_user_uuid_mismatch",
                    route_user=route.user_uuid,
                    write_target=route.write_target,
                    event_id=_event_id_of(document),
                )
                outcome.failed.append((document, mismatch))
                continue
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
            writable.append((route, document))

        if not writable:
            logger.error("bulk_index_nothing_writable", rejected=len(outcome.failed))
            return outcome

        response = await self._store.bulk(
            operations,
            # Wait for the write to be searchable? No - `refresh=False` keeps
            # ingest throughput high, and the 1s refresh interval means an
            # event is queryable well within any human timeframe.
            refresh=False,
        )

        outcome.took_ms = int(response.get("took", 0))
        if not response.get("errors"):
            outcome.succeeded = len(writable)
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
                _, duplicate_document = writable[position]
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
            _, document = writable[position]
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
        scope: UserScope,
        criteria: AuditSearchFilter,
        *,
        size: int,
        search_after: list[Any] | None = None,
        with_total: bool | int = False,
        source_fields: list[str] | None = None,
    ) -> SearchPage:
        """Run a user-scoped search."""
        targets, routing = self._resolve_read(scope)
        body = build_search_body(
            scope,
            criteria,
            size=size,
            max_window_days=self._max_window_days,
            default_window_days=self._default_window_days,
            search_after=search_after,
            track_total_hits=with_total,
            source_fields=source_fields,
            timeout=self._search_timeout,
            sort_date_format=self._store.sort_date_format,
        )

        response = await self._store.search(
            index=",".join(targets),
            body=body,
            routing=routing,
            # A user promoted to a dedicated stream has no stream yet until
            # its first event, so a missing index is expected rather than an error.
            ignore_unavailable=True,
            # Correctness over availability: a partial result set in a
            # compliance report is worse than an explicit failure, because the
            # reader cannot tell that records are missing.
            allow_partial_results=False,
            # Skips shards whose @timestamp range cannot match, which is the
            # single biggest win when querying a narrow window over years of
            # backing indices.
            pre_filter_shard_size=1,
        )
        return _to_page(response)

    async def aggregate(
        self,
        scope: UserScope,
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
            default_window_days=self._default_window_days,
            interval=interval,
            size=size,
        )
        response = await self._store.search(
            index=",".join(targets),
            body=body,
            routing=routing,
            ignore_unavailable=True,
            allow_partial_results=False,
            pre_filter_shard_size=1,
        )
        return dict(response.get("aggregations", {}))

    async def get_event(self, scope: UserScope, event_id: str) -> dict[str, Any] | None:
        """Fetch one event by id, still user-filtered.

        Deliberately a search rather than a GET by document id: a GET would
        return the document regardless of user, making an id-guessing attack a
        cross-user read. The id is unique, so the cost difference is trivial.
        """
        targets, routing = self._resolve_read(scope)
        filters: list[dict[str, Any]] = [{"term": {"event.id": event_id}}]
        if not scope.cross_user:
            filters.append({"term": {"user.uuid": scope.user_uuid}})

        response = await self._store.search(
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
    async def open_pit(self, scope: UserScope, *, keep_alive: str = "5m") -> str:
        """Open a point-in-time for a consistent export.

        Without a PIT, a long export paginating with `search_after` sees new
        documents arriving between pages, so the extract is a smear across time
        rather than a snapshot - unusable as evidence. A PIT freezes the view.
        """
        targets, _ = self._resolve_read(scope)
        return await self._store.open_pit(index=",".join(targets), keep_alive=keep_alive)

    async def search_pit(
        self,
        scope: UserScope,
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
            default_window_days=self._default_window_days,
            search_after=search_after,
            track_total_hits=False,
            timeout=self._search_timeout,
            # Ascending for exports: chronological order is what a reviewer
            # expects, and it matches hash-chain order for verification.
            ascending=True,
            sort_date_format=self._store.sort_date_format,
        )
        body["pit"] = {"id": pit_id, "keep_alive": keep_alive}
        response = await self._store.search(body=body)
        return _to_page(response)

    async def close_pit(self, pit_id: str) -> None:
        """Release a PIT. Safe to call twice.

        A leaked PIT pins Lucene segments and blocks disk reclamation, so this
        must run even on the error path - hence swallowing NotFoundError.
        """
        try:
            await self._store.close_pit(pit_id)
        except SearchNotFound:
            pass
        except Exception as exc:
            logger.warning("close_pit_failed", error=str(exc))

    # --------------------------------------------------------------- integrity
    async def fetch_chain_slice(
        self,
        *,
        chain_id: str,
        user_uuid: str,
        start_seq: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Fetch a contiguous chain slice in sequence order, for verification.

        Sorted by `integrity.seq` rather than `@timestamp`: the chain's order is
        its sequence, and two events can share a millisecond timestamp.
        """
        scope = UserScope(user_uuid=user_uuid)
        targets, routing = self._resolve_read(scope)
        response = await self._store.search(
            index=",".join(targets),
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"user.uuid": user_uuid}},
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
            allow_partial_results=False,
        )
        return [dict(hit["_source"]) for hit in response.get("hits", {}).get("hits", [])]

    async def count_by_key_id(self, *, user_uuid: str, key_id: str) -> int:
        """How many documents are protected by one PII key.

        Reported back on an erasure request so the DSR response can state how
        many records were affected - a documentation requirement under both
        GDPR Art. 19 and DPDP.
        """
        scope = UserScope(user_uuid=user_uuid)
        targets, routing = self._resolve_read(scope)
        return await self._store.count(
            index=",".join(targets),
            body={
                "query": {
                    "bool": {
                        "filter": [
                            {"term": {"user.uuid": user_uuid}},
                            {"term": {"pii.key_id": key_id}},
                        ]
                    }
                }
            },
            routing=routing,
            ignore_unavailable=True,
        )

    # ------------------------------------------------------------------ helpers
    def _resolve_read(self, scope: UserScope) -> tuple[tuple[str, ...], str | None]:
        """Translate a scope into concrete read targets and a routing key."""
        if scope.cross_user:
            # No routing key: a cross-user read genuinely must fan out.
            return self._router.cross_user_read_targets(), None
        decision = self._router.resolve(scope.user_uuid)
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


def _user_uuid_mismatch(document: dict[str, Any], route: RouteDecision) -> str | None:
    """Why this document must not be written to this route, or None if it may.

    The one invariant the whole isolation model rests on: a document lands in
    the stream belonging to the user it names. Everything else - the
    mandatory query filter, dedicated streams, `constant_keyword` - protects
    reads or depends on the engine. This protects the write, on every engine.

    A mismatch is a routing bug, never a transient fault, so the reason is
    phrased to be classified as permanent by `worker._is_permanent` and
    dead-lettered for a human rather than retried forever.
    """
    user = document.get("user")
    named = user.get("uuid") if isinstance(user, dict) else None
    if not named:
        return "user_uuid_mismatch: document carries no user.uuid"
    if str(named) != route.user_uuid:
        return (
            f"user_uuid_mismatch: document user.uuid={named!r} does not belong to "
            f"the route for {route.user_uuid!r} ({route.write_target})"
        )
    return None


def _event_id_of(document: dict[str, Any]) -> str | None:
    event = document.get("event")
    if isinstance(event, dict):
        value = event.get("id")
        return str(value) if value else None
    return None
