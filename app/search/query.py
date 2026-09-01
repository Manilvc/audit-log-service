"""Query construction.

This module is the tenant isolation boundary. The cluster runs a Basic licence,
so there is no document-level security to fall back on: if a query leaves here
without a tenant constraint, one customer can read another's audit trail. Two
structural decisions keep that from happening.

**Clients never send query DSL.** They send a typed `AuditSearchFilter`; the DSL
is assembled here. Accepting raw DSL would hand callers `script`, `regexp`,
wildcard-heavy and deeply-nested queries - a search-injection and
denial-of-service surface on a cluster holding every tenant's data.

**The tenant filter is applied by the builder, not the caller.** `build_query`
takes a `TenantScope` and there is no code path that omits it.
`tests/unit/test_tenant_isolation.py` asserts this over every filter
permutation.

Performance
-----------
Everything lands in `filter` context: no scoring, and the results are cacheable
in the node query cache. Audit search is "find matching records ordered by
time", never relevance ranking, so scoring would be pure overhead.

`track_total_hits` defaults to false. Counting every match across six years of
data costs far more than the page of results, and the UI needs "is there a next
page", not an exact total.

Deep pagination is `search_after`, never `from`/`size`: `from: 10000` forces
every shard to collect and sort 10 000 documents to discard them, while
`search_after` starts from the last sort value at effectively constant cost.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from app.domain.enums import EventCategory, Outcome, Severity

#: Sort is always (timestamp, tiebreaker). Timestamps collide constantly under
#: bulk ingest, so without a unique tiebreaker `search_after` would skip or
#: repeat rows across pages. `integrity.seq` is unique within a chain and
#: `event.id` is globally unique, giving a total order.
SORT_TIEBREAKER: Final[str] = "event.id"


class QueryValidationError(ValueError):
    """The filter is well-typed but not acceptable - e.g. an unbounded window."""


@dataclass(frozen=True, slots=True)
class TenantScope:
    """The authorised tenant boundary for one query.

    Constructed only by the auth layer from verified token claims, never from
    request parameters. `cross_tenant` requires the `audit:cross_tenant` scope
    and is audited at CRITICAL severity every time it is used.
    """

    tenant_id: str | None
    cross_tenant: bool = False
    issuer_id: str | None = None
    """Narrows to one issuer inside a tenant, for issuer-scoped operators."""
    actor_id: str | None = None
    """Restricts a caller to their own events - used for self-service history."""

    def __post_init__(self) -> None:
        if not self.cross_tenant and not self.tenant_id:
            raise QueryValidationError(
                "a tenant-scoped query requires tenant_id; "
                "cross-tenant access needs the audit:cross_tenant scope"
            )


@dataclass(slots=True)
class AuditSearchFilter:
    """Typed, validated search criteria. The only query input clients control."""

    start: datetime | None = None
    end: datetime | None = None
    actions: tuple[str, ...] = ()
    categories: tuple[EventCategory, ...] = ()
    outcomes: tuple[Outcome, ...] = ()
    severities: tuple[Severity, ...] = ()
    actor_ids: tuple[str, ...] = ()
    actor_types: tuple[str, ...] = ()
    session_id: str | None = None
    target_ids: tuple[str, ...] = ()
    target_types: tuple[str, ...] = ()
    issuer_id: str | None = None
    service_names: tuple[str, ...] = ()
    request_id: str | None = None
    trace_id: str | None = None
    event_ids: tuple[str, ...] = ()
    ip_prefix: str | None = None
    country_codes: tuple[str, ...] = ()
    http_status_min: int | None = None
    http_status_max: int | None = None
    label_terms: dict[str, str] | None = None
    """Exact key/value matches inside the `labels` flattened field."""
    text: str | None = None
    """Free-text match on `message`. Only useful when PII encryption is off,
    since an encrypted message is not indexed at all."""


def build_query(
    scope: TenantScope,
    criteria: AuditSearchFilter,
    *,
    max_window_days: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble the bool query, tenant constraint always included.

    Args:
        scope: the authorised boundary. Applied unconditionally.
        criteria: caller-supplied filters.
        max_window_days: refuses a window wider than this.
        now: injectable clock, for deterministic tests.

    Raises:
        QueryValidationError: the time window is missing, inverted or too wide.
    """
    reference = now or datetime.now(UTC)
    start, end = _resolve_window(criteria, reference, max_window_days)

    # ---- tenant constraint: first clause, never conditional on caller input --
    filters: list[dict[str, Any]] = []
    if not scope.cross_tenant:
        # `term` on a keyword is the cheapest possible filter, and on a
        # dedicated stream's `constant_keyword` it is resolved at rewrite time
        # for effectively zero cost.
        filters.append({"term": {"tenant.id": scope.tenant_id}})
    if scope.issuer_id:
        filters.append({"term": {"tenant.issuer_id": scope.issuer_id}})
    if scope.actor_id:
        # Self-service history: the caller may only see their own events, and
        # this cannot be widened by anything in `criteria`.
        filters.append({"term": {"actor.id": scope.actor_id}})

    # ---- time window: always bounded ---------------------------------------
    filters.append(
        {
            "range": {
                "@timestamp": {
                    "gte": start.isoformat(),
                    "lte": end.isoformat(),
                    # Explicit format avoids the cluster's default date parsing
                    # being locale- or version-sensitive.
                    "format": "strict_date_optional_time",
                }
            }
        }
    )

    # ---- caller filters, all in filter context ------------------------------
    _add_terms(filters, "event.action", criteria.actions)
    _add_terms(filters, "event.category", [c.value for c in criteria.categories])
    _add_terms(filters, "event.outcome", [o.value for o in criteria.outcomes])
    _add_terms(filters, "event.severity", [s.value for s in criteria.severities])
    _add_terms(filters, "actor.id", criteria.actor_ids)
    _add_terms(filters, "actor.type", criteria.actor_types)
    _add_terms(filters, "target.type", criteria.target_types)
    _add_terms(filters, "service.name", criteria.service_names)
    _add_terms(filters, "event.id", criteria.event_ids)
    _add_terms(filters, "source.country_code", criteria.country_codes)

    if criteria.session_id:
        filters.append({"term": {"actor.session_id": criteria.session_id}})
    if criteria.issuer_id and not scope.issuer_id:
        filters.append({"term": {"tenant.issuer_id": criteria.issuer_id}})
    if criteria.request_id:
        filters.append({"term": {"http.request_id": criteria.request_id}})
    if criteria.trace_id:
        filters.append({"term": {"http.trace_id": criteria.trace_id}})
    if criteria.ip_prefix:
        filters.append({"term": {"source.ip_prefix": criteria.ip_prefix}})

    if criteria.target_ids:
        # A bulk event records affected ids in `target.ids` while a single event
        # uses `target.id`, so "everything that touched record X" has to check
        # both or it silently misses every bulk operation.
        filters.append(
            {
                "bool": {
                    "should": [
                        {"terms": {"target.id": list(criteria.target_ids)}},
                        {"terms": {"target.ids": list(criteria.target_ids)}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    if criteria.http_status_min is not None or criteria.http_status_max is not None:
        bounds: dict[str, Any] = {}
        if criteria.http_status_min is not None:
            bounds["gte"] = criteria.http_status_min
        if criteria.http_status_max is not None:
            bounds["lte"] = criteria.http_status_max
        filters.append({"range": {"http.status_code": bounds}})

    if criteria.label_terms:
        for key, value in criteria.label_terms.items():
            # `flattened` subfields are addressed with a dotted path and match
            # exactly - no analysis, no wildcards.
            filters.append({"term": {f"labels.{key}": value}})

    query: dict[str, Any] = {"bool": {"filter": filters}}

    if criteria.text:
        # `must` rather than `filter` only because match_phrase on
        # match_only_text needs the analysed path; still unscored overall
        # because the sort is by time, so relevance is never consulted.
        query["bool"]["must"] = [
            {
                "match_phrase": {
                    "message": {"query": criteria.text[:512]},
                }
            }
        ]

    return query


def build_search_body(
    scope: TenantScope,
    criteria: AuditSearchFilter,
    *,
    size: int,
    max_window_days: int,
    search_after: list[Any] | None = None,
    track_total_hits: bool | int = False,
    source_fields: list[str] | None = None,
    timeout: str = "20s",
    ascending: bool = False,
) -> dict[str, Any]:
    """Full search body, tuned for the audit access pattern."""
    order = "asc" if ascending else "desc"
    body: dict[str, Any] = {
        "query": build_query(scope, criteria, max_window_days=max_window_days),
        "size": size,
        "sort": [
            {"@timestamp": {"order": order, "format": "strict_date_optional_time"}},
            {SORT_TIEBREAKER: {"order": order}},
        ],
        "track_total_hits": track_total_hits,
        "timeout": timeout,
    }
    if source_fields:
        # Fetching only the needed fields cuts _source decompression, which
        # dominates cost once documents carry sizeable `change` diffs.
        body["_source"] = source_fields
    if search_after:
        body["search_after"] = search_after
    return body


def build_aggregation_body(
    scope: TenantScope,
    criteria: AuditSearchFilter,
    *,
    group_by: str,
    max_window_days: int,
    interval: str | None = None,
    size: int = 50,
) -> dict[str, Any]:
    """Aggregation body for dashboards.

    `size: 0` means no hits are fetched or returned - a common and expensive
    mistake is to aggregate while also retrieving documents nobody reads.
    """
    body: dict[str, Any] = {
        "query": build_query(scope, criteria, max_window_days=max_window_days),
        "size": 0,
        "track_total_hits": False,
    }

    if interval:
        body["aggs"] = {
            "over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                },
                "aggs": {
                    "by_group": {
                        "terms": {
                            "field": group_by,
                            "size": size,
                            # Precomputed global ordinals: the right hint for a
                            # low-cardinality keyword like action or outcome.
                            "execution_hint": "global_ordinals",
                        }
                    }
                },
            }
        }
    else:
        body["aggs"] = {
            "by_group": {
                "terms": {
                    "field": group_by,
                    "size": size,
                    "execution_hint": "global_ordinals",
                    # Surfaces whether the terms list is complete - important
                    # when a compliance report claims to be exhaustive.
                    "show_term_doc_count_error": True,
                }
            }
        }
    return body


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
def _resolve_window(
    criteria: AuditSearchFilter,
    reference: datetime,
    max_window_days: int,
) -> tuple[datetime, datetime]:
    """Resolve and validate the time window.

    Defaults to the last 24 hours when neither bound is given. An unbounded
    audit query is a full-retention scan, which is both a performance incident
    and a sign the caller does not know what they are looking for.
    """
    end = criteria.end or reference
    start = criteria.start or (end - timedelta(days=1))

    if start.tzinfo is None or end.tzinfo is None:
        raise QueryValidationError("start and end must be timezone-aware")
    if start >= end:
        raise QueryValidationError("start must be strictly before end")
    if (end - start) > timedelta(days=max_window_days):
        raise QueryValidationError(
            f"query window of {(end - start).days} days exceeds the "
            f"{max_window_days}-day maximum; narrow the range or use the "
            "export endpoint for bulk extraction"
        )
    return start, end


def _add_terms(filters: list[dict[str, Any]], field: str, values: object) -> None:
    """Append a `terms` (or `term`) filter, skipping empty inputs.

    A single value becomes `term`: it skips the terms-set machinery and is
    measurably cheaper on the hot path.
    """
    if not values:
        return
    listed = list(values)  # type: ignore[call-overload]
    if not listed:
        return
    if len(listed) == 1:
        filters.append({"term": {field: listed[0]}})
    else:
        filters.append({"terms": {field: listed}})
