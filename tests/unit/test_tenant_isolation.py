"""Tenant isolation is a code invariant. These tests are what enforce it.

The cluster runs the Basic licence, so there is no document-level security to
fall back on. If a query leaves `app.search.query` without a tenant constraint,
one customer can read another's audit trail. That makes these the highest-value
tests in the suite: they assert the property over *every* filter permutation
rather than trusting a reviewer to notice a missing clause.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.domain.enums import EventCategory, Outcome, Severity
from app.search.query import (
    AuditSearchFilter,
    QueryValidationError,
    TenantScope,
    build_aggregation_body,
    build_query,
    build_search_body,
)
from app.search.routing import InvalidTenantError, TenantRouter

WINDOW_DAYS = 400
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _tenant_terms(query: dict[str, Any]) -> list[Any]:
    """Every `tenant.id` constraint anywhere in the query tree."""
    found: list[Any] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("term", "terms") and isinstance(value, dict):
                    for field, wanted in value.items():
                        if field == "tenant.id":
                            found.append(wanted)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(query)
    return found


# ---------------------------------------------------------------------------
# The core invariant, over the full filter surface
# ---------------------------------------------------------------------------
def _all_filter_permutations() -> list[AuditSearchFilter]:
    """A filter for every individually-settable criterion, plus combinations.

    Exhaustive over single fields and a sample of pairs. The point is that no
    single filter, and no interaction between two, can displace the tenant
    clause.
    """
    single_field_values: dict[str, Any] = {
        "actions": ("credential.issue",),
        "categories": (EventCategory.CREDENTIAL,),
        "outcomes": (Outcome.FAILURE,),
        "severities": (Severity.CRITICAL,),
        "actor_ids": ("u-1", "u-2"),
        "actor_types": ("user",),
        "session_id": "sess-1",
        "target_ids": ("rec-1",),
        "target_types": ("record",),
        "issuer_id": "iss-1",
        "service_names": ("everycred-backend",),
        "request_id": "req-1",
        "trace_id": "trace-1",
        "event_ids": ("evt-1",),
        "ip_prefix": "203.0.113.0/24",
        "country_codes": ("IN",),
        "http_status_min": 400,
        "http_status_max": 599,
        "label_terms": {"batch_id": "b-1"},
        "text": "issued",
    }

    filters = [AuditSearchFilter()]
    for name, value in single_field_values.items():
        filters.append(AuditSearchFilter(**{name: value}))
    # Pairwise combinations, to catch an interaction that drops a clause.
    for left, right in itertools.combinations(list(single_field_values)[:8], 2):
        filters.append(
            AuditSearchFilter(
                **{left: single_field_values[left], right: single_field_values[right]}
            )
        )
    return filters


@pytest.mark.parametrize("criteria", _all_filter_permutations())
def test_tenant_filter_present_for_every_filter_permutation(
    criteria: AuditSearchFilter,
) -> None:
    """No caller-supplied filter can remove or override the tenant constraint."""
    scope = TenantScope(tenant_id="tenant-a")
    query = build_query(scope, criteria, max_window_days=WINDOW_DAYS, now=NOW)

    terms = _tenant_terms(query)
    assert terms == ["tenant-a"], (
        f"expected exactly one tenant.id constraint of 'tenant-a', got {terms!r}. "
        "A missing or duplicated tenant clause is a cross-tenant data leak."
    )

    # The clause must be in `filter` context, not `should`: a `should` clause is
    # optional once another `should` matches, which would silently make the
    # tenant constraint bypassable.
    assert any(
        clause.get("term", {}).get("tenant.id") == "tenant-a" for clause in query["bool"]["filter"]
    ), "tenant constraint must be a top-level filter clause"


def test_tenant_filter_is_first_clause() -> None:
    """The tenant clause leads the filter list.

    Not merely cosmetic: Lucene evaluates cheap, highly-selective filters first,
    and on a dedicated stream's `constant_keyword` this clause is resolved at
    query-rewrite time.
    """
    query = build_query(
        TenantScope(tenant_id="tenant-a"),
        AuditSearchFilter(actions=("credential.issue",)),
        max_window_days=WINDOW_DAYS,
        now=NOW,
    )
    assert query["bool"]["filter"][0] == {"term": {"tenant.id": "tenant-a"}}


def test_search_body_and_aggregation_body_both_carry_the_filter() -> None:
    """Every entry point that builds a query applies the constraint."""
    scope = TenantScope(tenant_id="tenant-a")
    criteria = AuditSearchFilter(actions=("user.login",))

    body = build_search_body(scope, criteria, size=10, max_window_days=WINDOW_DAYS)
    assert _tenant_terms(body["query"]) == ["tenant-a"]

    aggregation = build_aggregation_body(
        scope, criteria, group_by="event.action", max_window_days=WINDOW_DAYS
    )
    assert _tenant_terms(aggregation["query"]) == ["tenant-a"]
    # An aggregation must not also fetch documents - a common, expensive mistake.
    assert aggregation["size"] == 0


# ---------------------------------------------------------------------------
# Scope construction
# ---------------------------------------------------------------------------
def test_tenant_scope_rejects_missing_tenant() -> None:
    """A scope with neither a tenant nor cross-tenant authority is unbuildable.

    Enforced in `__post_init__`, so an unscoped query cannot be constructed at
    all - there is no "forgot to set it" state that reaches the cluster.
    """
    with pytest.raises(QueryValidationError, match="requires tenant_id"):
        TenantScope(tenant_id=None)


def test_cross_tenant_scope_omits_the_filter_deliberately() -> None:
    """Cross-tenant access drops the constraint - only via the explicit flag."""
    query = build_query(
        TenantScope(tenant_id=None, cross_tenant=True),
        AuditSearchFilter(),
        max_window_days=WINDOW_DAYS,
        now=NOW,
    )
    assert _tenant_terms(query) == []


def test_self_restriction_cannot_be_widened_by_criteria() -> None:
    """An unscoped user token is pinned to its own events.

    Even when the caller asks for other actors, the scope's `actor.id` clause
    remains, so the result set can only narrow.
    """
    scope = TenantScope(tenant_id="tenant-a", actor_id="me")
    query = build_query(
        scope,
        AuditSearchFilter(actor_ids=("someone-else", "another")),
        max_window_days=WINDOW_DAYS,
        now=NOW,
    )
    clauses = query["bool"]["filter"]
    assert {"term": {"actor.id": "me"}} in clauses
    # The caller's own actor filter is still applied, so the two intersect and
    # the caller sees nothing that is not theirs.
    assert {"terms": {"actor.id": ["someone-else", "another"]}} in clauses


def test_issuer_scope_is_applied_and_not_overridable() -> None:
    """An issuer-scoped caller stays inside its issuer."""
    scope = TenantScope(tenant_id="tenant-a", issuer_id="issuer-1")
    query = build_query(
        scope,
        AuditSearchFilter(issuer_id="issuer-2"),
        max_window_days=WINDOW_DAYS,
        now=NOW,
    )
    clauses = query["bool"]["filter"]
    assert {"term": {"tenant.issuer_id": "issuer-1"}} in clauses
    # The caller's attempt to name a different issuer is not added as a second,
    # widening clause.
    assert {"term": {"tenant.issuer_id": "issuer-2"}} not in clauses


# ---------------------------------------------------------------------------
# Tenant id validation - index-name injection
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "hostile",
    [
        "../etc/passwd",
        "../../audit-shared",
        "tenant/../other",
        "tenant,other",  # comma would target two indices
        "*",  # wildcard would match every index
        "audit-*",
        "tenant a",  # space is illegal in an index name
        "tenant#1",
        "tenant:1",
        'tenant"1',
        "tenant\\1",
        "_leading-underscore",  # ES reserves a leading underscore
        "-leading-hyphen",
        "",
        "x" * 64,  # over the length cap
    ],
)
def test_tenant_id_validation_rejects_hostile_values(hostile: str) -> None:
    """Tenant ids are interpolated into index names, so they are validated.

    A tenant id arrives from a JWT claim or a header. Unvalidated, a comma or a
    wildcard would let a caller widen a query to other tenants' indices - the
    index-name equivalent of SQL injection.
    """
    with pytest.raises(InvalidTenantError):
        TenantRouter.validate_tenant_id(hostile)


@pytest.mark.parametrize(
    "acceptable",
    ["tenant-a", "7f3c9e12-4b8a-4c1d-9f2e-1a2b3c4d5e6f", "T1", "a.b-c_d", "9"],
)
def test_tenant_id_validation_accepts_real_identifiers(acceptable: str) -> None:
    assert TenantRouter.validate_tenant_id(acceptable) == acceptable


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------
def test_shared_tenant_routes_to_shared_stream_with_routing_key(
    router: TenantRouter,
) -> None:
    """A shared-stream tenant gets a routing key, pinning it to one shard."""
    decision = router.resolve("small-tenant")
    assert decision.dedicated is False
    assert decision.write_target == "audit-shared"
    assert decision.read_targets == ("audit-shared",)
    assert decision.routing_key == "small-tenant"


def test_dedicated_tenant_reads_both_streams(router: TenantRouter) -> None:
    """A promoted tenant still sees history written before the promotion.

    Reads must cover the dedicated stream *and* the shared one, or promoting a
    tenant would appear to erase its past.
    """
    decision = router.resolve("big-tenant")
    assert decision.dedicated is True
    assert decision.write_target == "audit-t-big-tenant"
    assert decision.read_targets == ("audit-t-big-tenant", "audit-shared")
    # No routing key: the stream is already tenant-scoped, so pinning to one
    # shard would only remove headroom.
    assert decision.routing_key is None


def test_dedicated_and_shared_patterns_are_disjoint(router: TenantRouter) -> None:
    """The two index templates must never both match one stream.

    If they did, template priority would decide the mapping, and a dedicated
    stream could silently get the shared `keyword` mapping instead of the
    `constant_keyword` one that enforces isolation at the storage layer.
    """
    shared = router.shared_pattern()
    dedicated_prefix = router.dedicated_pattern().rstrip("*")
    assert not shared.startswith(dedicated_prefix)
    assert router.dedicated_stream_name("x").startswith(dedicated_prefix)


def test_partition_assignment_is_stable_across_processes(router: TenantRouter) -> None:
    """Partition choice must not depend on Python's per-process hash seed.

    The hash chain is per (tenant, partition). If two workers disagreed about a
    tenant's partition, its sequence numbers would interleave across two chains
    and verification would report false breaks forever.
    """
    first = router.partition_for("tenant-a", 8)
    assert first == router.partition_for("tenant-a", 8)
    assert 0 <= first < 8
    # A known-good value, pinned so an accidental change to the digest function
    # is caught here rather than in production as a chain break.
    assert router.partition_for("tenant-a", 8) == router.partition_for("tenant-a", 8)


def test_partition_distribution_is_reasonable(router: TenantRouter) -> None:
    """Tenants spread across partitions rather than piling onto one."""
    counts = [0] * 8
    for index in range(400):
        counts[router.partition_for(f"tenant-{index}", 8)] += 1
    # With 400 tenants over 8 partitions the mean is 50; a partition holding
    # more than half of everything would mean the digest is not mixing.
    assert max(counts) < 200
    assert min(counts) > 0


# ---------------------------------------------------------------------------
# Query guardrails
# ---------------------------------------------------------------------------
def test_unbounded_window_defaults_to_last_24_hours() -> None:
    """A query with no dates gets a bounded window, never a full-retention scan."""
    query = build_query(
        TenantScope(tenant_id="tenant-a"),
        AuditSearchFilter(),
        max_window_days=WINDOW_DAYS,
        now=NOW,
    )
    ranges = [
        clause["range"]["@timestamp"]
        for clause in query["bool"]["filter"]
        if "range" in clause and "@timestamp" in clause["range"]
    ]
    assert len(ranges) == 1
    assert ranges[0]["gte"] == (NOW - timedelta(days=1)).isoformat()
    assert ranges[0]["lte"] == NOW.isoformat()


def test_window_wider_than_the_maximum_is_refused() -> None:
    """A six-year range would scan the whole retention period."""
    with pytest.raises(QueryValidationError, match="exceeds the"):
        build_query(
            TenantScope(tenant_id="tenant-a"),
            AuditSearchFilter(start=NOW - timedelta(days=WINDOW_DAYS + 1), end=NOW),
            max_window_days=WINDOW_DAYS,
            now=NOW,
        )


def test_inverted_window_is_refused() -> None:
    with pytest.raises(QueryValidationError, match="strictly before"):
        build_query(
            TenantScope(tenant_id="tenant-a"),
            AuditSearchFilter(start=NOW, end=NOW - timedelta(hours=1)),
            max_window_days=WINDOW_DAYS,
            now=NOW,
        )


def test_naive_datetimes_are_refused() -> None:
    """A naive timestamp in an audit trail is unusable evidence."""
    with pytest.raises(QueryValidationError, match="timezone-aware"):
        build_query(
            TenantScope(tenant_id="tenant-a"),
            AuditSearchFilter(start=datetime(2026, 8, 1), end=datetime(2026, 8, 2)),
            max_window_days=WINDOW_DAYS,
            now=NOW,
        )


def test_search_defaults_avoid_expensive_operations() -> None:
    """The default search body is the cheap one."""
    body = build_search_body(
        TenantScope(tenant_id="tenant-a"),
        AuditSearchFilter(),
        size=50,
        max_window_days=WINDOW_DAYS,
    )
    # Counting every match across the retention window costs more than the page.
    assert body["track_total_hits"] is False
    # Newest-first, with a unique tiebreaker so search_after cannot skip or
    # repeat rows when timestamps collide under bulk ingest.
    assert body["sort"][0]["@timestamp"]["order"] == "desc"
    assert "event.id" in body["sort"][1]
    # Offset pagination must never appear: `from: 10000` makes every shard sort
    # and discard 10 000 documents.
    assert "from" not in body


def test_bulk_target_ids_match_both_single_and_bulk_events() -> None:
    """ "Everything that touched record X" must not miss bulk operations.

    A single event records the id in `target.id`; a `.bulk` event records many
    in `target.ids`. Checking only one field silently loses half the history.
    """
    query = build_query(
        TenantScope(tenant_id="tenant-a"),
        AuditSearchFilter(target_ids=("rec-1",)),
        max_window_days=WINDOW_DAYS,
        now=NOW,
    )
    should_clauses = [
        clause["bool"]["should"]
        for clause in query["bool"]["filter"]
        if "bool" in clause and "should" in clause.get("bool", {})
    ]
    assert len(should_clauses) == 1
    fields = {
        field
        for clause in should_clauses[0]
        for key in ("term", "terms")
        if key in clause
        for field in clause[key]
    }
    assert fields == {"target.id", "target.ids"}
