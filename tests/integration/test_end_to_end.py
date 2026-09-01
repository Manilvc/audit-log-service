"""End-to-end tests against live Elasticsearch and Redis.

    docker compose up -d elasticsearch redis
    uv run pytest -m integration

These cover what unit tests structurally cannot: that the mapping Elasticsearch
actually installs behaves as intended. Several of the isolation and privacy
guarantees are enforced *by the cluster* rather than by application code -
`constant_keyword` rejecting a wrong-tenant document, `enabled: false` making
ciphertext unsearchable, `op_type: create` rejecting a duplicate. A mock cannot
verify any of those.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from elasticsearch import AsyncElasticsearch, BadRequestError

from app.core.config import Settings, get_settings
from app.core.integrity import GENESIS_HASH, compute_hash, verify_chain
from app.queue.worker import _is_permanent
from app.search.bootstrap import (
    bootstrap_cluster,
    dedicated_template_name,
    keyring_index_name,
    shared_template_name,
)
from app.search.client import build_client, ping
from app.search.mappings import dedicated_index_template, shared_index_template
from app.search.query import AuditSearchFilter, TenantScope
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter

pytestmark = pytest.mark.integration

# A unique prefix per run, so a test run never collides with real data or with a
# previous run's leftovers.
RUN_ID = uuid.uuid4().hex[:8]
TENANT_A = f"itest-{RUN_ID}-a"
TENANT_B = f"itest-{RUN_ID}-b"
DEDICATED_TENANT = f"itest-{RUN_ID}-ded"


@pytest.fixture(scope="module")
def itest_settings() -> Iterator[Settings]:
    """Settings pointed at the local stack, with an isolated index prefix.

    Previous values are captured and restored on teardown. `get_settings` is an
    lru_cache over process-wide environment state, so leaving these set would
    change what the unit tests see depending on collection order - integration
    is collected before unit, so the leak was silently rewriting the shared
    router fixture's index prefix.
    """
    overrides = {
        "INDEX_PREFIX": f"itest-{RUN_ID}",
        "SHARED_DATA_STREAM": f"itest-{RUN_ID}-shared",
        "DEDICATED_TENANTS": DEDICATED_TENANT,
        "ILM_POLICY_NAME": f"itest-{RUN_ID}-retention",
        # A single-node development cluster cannot allocate replicas.
        "INDEX_REPLICAS": "0",
        "SHARED_SHARD_COUNT": "2",
    }
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    get_settings.cache_clear()
    try:
        yield get_settings()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


@pytest.fixture(scope="module")
def router(itest_settings: Settings) -> TenantRouter:
    return TenantRouter(
        shared_stream=itest_settings.SHARED_DATA_STREAM,
        index_prefix=itest_settings.INDEX_PREFIX,
        dedicated_tenants=itest_settings.dedicated_tenant_set,
    )


@pytest.fixture(scope="module")
async def es(itest_settings: Settings, router: TenantRouter) -> AsyncIterator[AsyncElasticsearch]:
    client = build_client(itest_settings)
    if not await ping(client):
        await client.close()
        pytest.skip("Elasticsearch is not reachable; run `docker compose up -d`")

    await bootstrap_cluster(client, itest_settings, router)
    yield client

    # Tear down everything this run created. Audit indices are append-only in
    # production, but a test run must not leave state behind.
    #
    # Suppressed rather than logged: a stream that was never created has nothing
    # to delete, and a cleanup failure must not mask the test result.
    for name in (
        router.shared_pattern(),
        router.dedicated_stream_name(DEDICATED_TENANT),
    ):
        with contextlib.suppress(Exception):
            await client.indices.delete_data_stream(name=name)
    with contextlib.suppress(Exception):
        await client.indices.delete(index=keyring_index_name(itest_settings))
    # Templates too: they are named from INDEX_PREFIX, so leaving this run's
    # behind would accumulate one dead template per run and, worse, keep
    # matching patterns that no longer have a stream.
    for template in (
        shared_template_name(itest_settings),
        dedicated_template_name(itest_settings),
    ):
        with contextlib.suppress(Exception):
            await client.indices.delete_index_template(name=template)
    with contextlib.suppress(Exception):
        await client.ilm.delete_lifecycle(name=itest_settings.ILM_POLICY_NAME)
    await client.close()


@pytest.fixture
def repository(
    es: AsyncElasticsearch, router: TenantRouter, itest_settings: Settings
) -> AuditRepository:
    return AuditRepository(
        es,
        router,
        max_window_days=itest_settings.MAX_QUERY_WINDOW_DAYS,
        search_timeout=itest_settings.SEARCH_TIMEOUT,
    )


def _document(
    tenant_id: str,
    *,
    seq: int = 0,
    chain_id: str | None = None,
    action: str = "credential.issue",
    actor_id: str = "u-1",
    event_id: str | None = None,
    prev_hash: str = GENESIS_HASH,
) -> dict[str, Any]:
    """A complete, correctly chained document, as the worker would produce."""
    chain = chain_id or f"{tenant_id}:0"
    document: dict[str, Any] = {
        "@timestamp": datetime.now(UTC).isoformat(),
        "event": {
            "id": event_id or str(uuid.uuid4()),
            "action": action,
            "category": "credential",
            "type": "creation",
            "outcome": "success",
            "severity": "info",
        },
        "tenant": {"id": tenant_id},
        "actor": {"id": actor_id, "type": "user"},
        "target": {"type": "credential", "id": f"vc-{seq}"},
        "source": {"country_code": "IN", "ip_prefix": "203.0.113.0/24"},
        "service": {"name": "itest"},
        "labels": {"run": RUN_ID},
    }
    digest = compute_hash(chain, seq, prev_hash, document)
    document["integrity"] = {
        "seq": seq,
        "prev_hash": prev_hash,
        "hash": digest,
        "algo": "sha256",
        "chain_id": chain,
    }
    return document


async def _refresh(es: AsyncElasticsearch, router: TenantRouter) -> None:
    """Make writes visible. Only needed in tests: production reads tolerate 1s."""
    await es.indices.refresh(
        index=f"{router.shared_pattern()},{router.dedicated_pattern()}",
        ignore_unavailable=True,
    )


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
async def test_bootstrap_creates_the_expected_topology(
    es: AsyncElasticsearch, itest_settings: Settings, router: TenantRouter
) -> None:
    """The topology is applied from code, so a fresh cluster cannot drift."""
    policy = await es.ilm.get_lifecycle(name=itest_settings.ILM_POLICY_NAME)
    phases = policy[itest_settings.ILM_POLICY_NAME]["policy"]["phases"]
    assert set(phases) == {"hot", "warm", "cold", "delete"}
    # Six years (HIPAA 164.316(b)(2)(i)).
    assert phases["delete"]["min_age"] == f"{itest_settings.RETENTION_DAYS}d"

    assert await es.indices.exists(index=keyring_index_name(itest_settings))
    streams = await es.indices.get_data_stream(name=router.shared_pattern())
    assert streams["data_streams"]


async def test_bootstrap_is_idempotent(
    es: AsyncElasticsearch, itest_settings: Settings, router: TenantRouter
) -> None:
    """It runs on every startup, so a second pass must be a no-op."""
    await bootstrap_cluster(es, itest_settings, router)
    await bootstrap_cluster(es, itest_settings, router)


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------
async def test_write_and_read_round_trip(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    route = router.resolve(TENANT_A)
    outcome = await repository.bulk_index(
        [(route, _document(TENANT_A, seq=index)) for index in range(5)]
    )
    assert outcome.all_succeeded, outcome.failed
    assert outcome.succeeded == 5

    await _refresh(es, router)
    page = await repository.search(TenantScope(tenant_id=TENANT_A), AuditSearchFilter(), size=10)
    assert len(page.events) == 5


async def test_duplicate_event_id_is_rejected_giving_exactly_once(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """The property that makes the at-least-once queue safe.

    A redelivered message must not produce a second copy of the event. `_id` is
    the event id and `op_type: create` refuses to overwrite, so the retry is a
    409 that the repository counts as success.
    """
    route = router.resolve(TENANT_A)
    event_id = f"fixed-{uuid.uuid4().hex}"
    document = _document(TENANT_A, seq=100, event_id=event_id)

    first = await repository.bulk_index([(route, document)])
    assert first.succeeded == 1

    # Simulate a queue redelivery of the identical event.
    second = await repository.bulk_index([(route, document)])
    assert second.all_succeeded
    assert second.succeeded == 1

    await _refresh(es, router)
    page = await repository.search(
        TenantScope(tenant_id=TENANT_A),
        AuditSearchFilter(event_ids=(event_id,)),
        size=10,
        with_total=100,
    )
    assert len(page.events) == 1, "the event was stored twice"


async def test_unmapped_field_is_rejected_by_strict_mapping(
    repository: AuditRepository, router: TenantRouter
) -> None:
    """`dynamic: strict` makes an undeclared field a loud error.

    A silently-unindexed field would be discovered during an incident, when the
    data is needed and unsearchable. The rejection routes the event to the
    dead-letter queue instead, which is alerted on.
    """
    route = router.resolve(TENANT_A)
    document = _document(TENANT_A, seq=200)
    document["totally_undeclared_field"] = "surprise"

    outcome = await repository.bulk_index([(route, document)])
    assert not outcome.all_succeeded
    reason = outcome.failed[0][1]
    assert "strict_dynamic_mapping_exception" in reason, reason
    # The worker must classify this as permanent and dead-letter it rather than
    # retrying a document that will be rejected identically forever.
    assert _is_permanent(reason)


# ---------------------------------------------------------------------------
# Tenant isolation, enforced by the cluster
# ---------------------------------------------------------------------------
async def test_tenant_cannot_read_another_tenants_events(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """The isolation guarantee, verified against a real index."""
    await repository.bulk_index(
        [(router.resolve(TENANT_A), _document(TENANT_A, seq=300, actor_id="alice"))]
    )
    await repository.bulk_index(
        [(router.resolve(TENANT_B), _document(TENANT_B, seq=300, actor_id="bob"))]
    )
    await _refresh(es, router)

    a_page = await repository.search(TenantScope(tenant_id=TENANT_A), AuditSearchFilter(), size=100)
    a_tenants = {event["tenant"]["id"] for event in a_page.events}
    assert a_tenants == {TENANT_A}

    # Even explicitly asking for the other tenant's actor returns nothing.
    leaked = await repository.search(
        TenantScope(tenant_id=TENANT_A),
        AuditSearchFilter(actor_ids=("bob",)),
        size=100,
    )
    assert leaked.events == []


async def test_get_event_by_id_is_tenant_filtered(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """Guessing an event id must not cross a tenant boundary.

    This is why `get_event` is a filtered search rather than a document GET - a
    GET would return the document regardless of tenant.
    """
    event_id = f"cross-{uuid.uuid4().hex}"
    await repository.bulk_index(
        [(router.resolve(TENANT_B), _document(TENANT_B, seq=400, event_id=event_id))]
    )
    await _refresh(es, router)

    assert await repository.get_event(TenantScope(tenant_id=TENANT_B), event_id)
    assert await repository.get_event(TenantScope(tenant_id=TENANT_A), event_id) is None


async def test_dedicated_stream_rejects_a_wrong_tenant_document(
    es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """`constant_keyword` makes cross-tenant contamination impossible.

    A dedicated stream's backing index adopts the tenant id of its first
    document; Elasticsearch then refuses any document with a different one. This
    is a storage-layer guarantee, not an application check, so it holds even if
    the routing code is wrong.
    """
    stream = router.dedicated_stream_name(DEDICATED_TENANT)

    # First document establishes the constant value.
    await es.index(
        index=stream,
        document=_document(DEDICATED_TENANT, seq=0),
        op_type="create",
        refresh="wait_for",
    )

    with pytest.raises(BadRequestError) as caught:
        await es.index(
            index=stream,
            document=_document("some-other-tenant", seq=1),
            op_type="create",
            refresh="wait_for",
        )
    message = str(caught.value)
    assert "constant_keyword" in message, message


async def test_dedicated_tenant_reads_both_streams(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """History written before promotion must stay visible."""
    # An event in the shared stream, as if written before promotion.
    shared_route = router.resolve(TENANT_A)
    pre_promotion = _document(DEDICATED_TENANT, seq=500)
    await repository.bulk_index([(shared_route, pre_promotion)])
    await _refresh(es, router)

    page = await repository.search(
        TenantScope(tenant_id=DEDICATED_TENANT), AuditSearchFilter(), size=100
    )
    ids = {event["event"]["id"] for event in page.events}
    assert pre_promotion["event"]["id"] in ids, "pre-promotion history is not visible"


# ---------------------------------------------------------------------------
# Privacy, enforced by the mapping
# ---------------------------------------------------------------------------
async def test_ciphertext_is_not_searchable(
    es: AsyncElasticsearch, router: TenantRouter, repository: AuditRepository
) -> None:
    """`pii_ct` is mapped `enabled: false`, so encrypted blobs cannot be queried.

    Without this, a wildcard or match_all query over the ciphertext field could
    confirm the presence of a known value.
    """
    document = _document(TENANT_A, seq=600)
    document["pii_ct"] = {"actor.email": "v1:nonce:ciphertextblob"}
    document["pii"] = {"encrypted": True, "key_id": "k-1", "fields": ["actor.email"]}

    outcome = await repository.bulk_index([(router.resolve(TENANT_A), document)])
    assert outcome.all_succeeded, outcome.failed
    await _refresh(es, router)

    # The value is retrievable from _source...
    stored = await repository.get_event(TenantScope(tenant_id=TENANT_A), document["event"]["id"])
    assert stored is not None
    assert stored["pii_ct"]["actor.email"].startswith("v1:")

    # ...but not searchable. `enabled: false` means the subfields are unmapped,
    # so a term query matches nothing rather than confirming the value exists.
    # That is the guarantee: no oracle over encrypted content.
    response = await es.search(
        index=router.shared_pattern(),
        body={
            "query": {"term": {"pii_ct.actor.email": "v1:nonce:ciphertextblob"}},
            "track_total_hits": True,
        },
        ignore_unavailable=True,
    )
    assert response["hits"]["total"]["value"] == 0


async def test_pii_fields_are_absent_from_the_mapping(
    es: AsyncElasticsearch, itest_settings: Settings
) -> None:
    """`actor.email` is deliberately unmapped.

    Leaving it out means a future emitter writing plaintext there is rejected by
    `dynamic: strict` rather than quietly indexing personal data.
    """
    template = shared_index_template(
        name_pattern="x",
        shards=1,
        replicas=0,
        ilm_policy_name=itest_settings.ILM_POLICY_NAME,
    )
    actor_properties = template["template"]["mappings"]["properties"]["actor"]["properties"]
    assert "email" not in actor_properties
    assert "name" not in actor_properties
    assert "phone" not in actor_properties
    # The full IP is likewise unmapped; only the truncated prefix is indexed.
    source_properties = template["template"]["mappings"]["properties"]["source"]["properties"]
    assert "ip" not in source_properties
    assert "ip_prefix" in source_properties


def test_shared_and_dedicated_templates_differ_only_where_intended(
    itest_settings: Settings,
) -> None:
    """The dedicated template's higher priority and constant_keyword matter."""
    shared = shared_index_template(name_pattern="a", shards=3, replicas=0, ilm_policy_name="p")
    dedicated = dedicated_index_template(
        name_pattern="b", shards=1, replicas=0, ilm_policy_name="p"
    )
    assert dedicated["priority"] > shared["priority"]
    assert (
        shared["template"]["mappings"]["properties"]["tenant"]["properties"]["id"]["type"]
        == "keyword"
    )
    assert (
        dedicated["template"]["mappings"]["properties"]["tenant"]["properties"]["id"]["type"]
        == "constant_keyword"
    )


# ---------------------------------------------------------------------------
# Pagination, export and integrity over real data
# ---------------------------------------------------------------------------
async def test_cursor_pagination_covers_every_event_exactly_once(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """`search_after` must neither skip nor repeat a row.

    Timestamps collide constantly under bulk ingest, which is why the sort
    carries a unique tiebreaker. Without it, pages would overlap.
    """
    tenant = f"{TENANT_A}-page"
    route = router.resolve(tenant)
    expected = {
        document["event"]["id"]: document
        for document in (_document(tenant, seq=index) for index in range(25))
    }
    await repository.bulk_index([(route, doc) for doc in expected.values()])
    await _refresh(es, router)

    seen: list[str] = []
    cursor: list[Any] | None = None
    for _ in range(10):  # bounded, so a paging bug fails rather than loops
        page = await repository.search(
            TenantScope(tenant_id=tenant),
            AuditSearchFilter(),
            size=7,
            search_after=cursor,
        )
        if not page.events:
            break
        seen.extend(event["event"]["id"] for event in page.events)
        if len(page.events) < 7:
            break
        cursor = page.next_cursor

    assert len(seen) == len(set(seen)), "pagination returned a duplicate"
    assert set(seen) == set(expected), "pagination skipped an event"


async def test_point_in_time_export_is_a_consistent_snapshot(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """A PIT freezes the view, so an export is a snapshot rather than a smear."""
    tenant = f"{TENANT_A}-pit"
    route = router.resolve(tenant)
    await repository.bulk_index([(route, _document(tenant, seq=index)) for index in range(10)])
    await _refresh(es, router)

    pit_id = await repository.open_pit(TenantScope(tenant_id=tenant))
    try:
        # Documents arriving after the PIT opened must not appear in it.
        await repository.bulk_index(
            [(route, _document(tenant, seq=index)) for index in range(10, 20)]
        )
        await _refresh(es, router)

        collected: list[dict[str, Any]] = []
        cursor: list[Any] | None = None
        while True:
            page = await repository.search_pit(
                TenantScope(tenant_id=tenant),
                AuditSearchFilter(),
                pit_id=pit_id,
                size=5,
                search_after=cursor,
            )
            if not page.events:
                break
            collected.extend(page.events)
            if len(page.events) < 5:
                break
            cursor = page.next_cursor

        assert len(collected) == 10, "the snapshot included post-PIT documents"
    finally:
        await repository.close_pit(pit_id)


async def test_chain_written_to_the_cluster_verifies_after_round_trip(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """The hash must survive storage and retrieval.

    Elasticsearch may reorder `_source` keys, so this is the test that proves
    canonical re-serialisation makes verification work on retrieved documents
    rather than only on in-memory ones.
    """
    tenant = f"{TENANT_A}-chain"
    chain_id = f"{tenant}:0"
    route = router.resolve(tenant)

    documents: list[dict[str, Any]] = []
    prev = GENESIS_HASH
    for seq in range(15):
        document = _document(tenant, seq=seq, chain_id=chain_id, prev_hash=prev)
        prev = document["integrity"]["hash"]
        documents.append(document)

    outcome = await repository.bulk_index([(route, doc) for doc in documents])
    assert outcome.all_succeeded, outcome.failed
    await _refresh(es, router)

    retrieved = await repository.fetch_chain_slice(
        chain_id=chain_id, tenant_id=tenant, start_seq=0, limit=100
    )
    assert len(retrieved) == 15

    result = verify_chain(chain_id, retrieved, expect_contiguous_from=0)
    assert result.intact, [break_.detail for break_ in result.breaks]
    assert result.verified_count == 15


async def test_aggregation_returns_buckets(
    repository: AuditRepository, es: AsyncElasticsearch, router: TenantRouter
) -> None:
    tenant = f"{TENANT_A}-agg"
    route = router.resolve(tenant)
    await repository.bulk_index(
        [
            (route, _document(tenant, seq=0, action="credential.issue")),
            (route, _document(tenant, seq=1, action="credential.issue")),
            (route, _document(tenant, seq=2, action="credential.revoke")),
        ]
    )
    await _refresh(es, router)

    aggregations = await repository.aggregate(
        TenantScope(tenant_id=tenant), AuditSearchFilter(), group_by="event.action"
    )
    buckets = {bucket["key"]: bucket["doc_count"] for bucket in aggregations["by_group"]["buckets"]}
    assert buckets["credential.issue"] == 2
    assert buckets["credential.revoke"] == 1


async def test_dedicated_stream_does_not_require_routing(
    es: AsyncElasticsearch, router: TenantRouter
) -> None:
    """Regression guard for the `allow_custom_routing` / `_routing` coupling.

    Enabling `allow_custom_routing` on a data stream template makes
    Elasticsearch set `_routing: {required: true}` on every backing index. The
    dedicated template therefore leaves the flag off, because the router supplies
    no routing key for a dedicated tenant. With the flag on, every write to a
    dedicated stream fails with `routing_missing_exception` - a total ingest
    outage for exactly the highest-volume tenants.

    This asserts the cluster-side facts, so re-adding the flag fails here.
    """
    stream = router.dedicated_stream_name(DEDICATED_TENANT)
    streams = await es.indices.get_data_stream(name=stream)
    assert streams["data_streams"][0].get("allow_custom_routing") is False

    backing = streams["data_streams"][0]["indices"][0]["index_name"]
    mapping = await es.indices.get_mapping(index=backing)
    assert mapping[backing]["mappings"].get("_routing") is None

    # And the shared stream, which does supply routing, has it required.
    shared = await es.indices.get_data_stream(name=router.shared_pattern())
    assert shared["data_streams"][0].get("allow_custom_routing") is True
