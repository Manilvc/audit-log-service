"""End-to-end tests against a live search store and Redis.

    docker compose up -d elasticsearch redis     # SEARCH_BACKEND=elasticsearch
    docker compose up -d opensearch redis        # SEARCH_BACKEND=opensearch
    uv run pytest -m integration

The suite runs against whichever engine `SEARCH_BACKEND` names, because these
cover what unit tests structurally cannot: that the mapping the engine actually
installs behaves as intended. Several of the isolation and privacy guarantees
are enforced *by the store* rather than by application code - `enabled: false`
making ciphertext unsearchable, `op_type: create` rejecting a duplicate,
`dynamic: strict` rejecting an undeclared field. A mock cannot verify any of
those, and neither can the other engine: that is the point of running twice.

Where the engines genuinely differ - the retention policy document, and
Elastic's `constant_keyword` backstop - the test forks explicitly rather than
asserting one engine's shape on both.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from elasticsearch import BadRequestError

from app.core.config import Settings, get_settings
from app.core.integrity import GENESIS_HASH, compute_hash, verify_chain
from app.queue.worker import _is_permanent
from app.search.backends import (
    ElasticsearchBackend,
    OpenSearchBackend,
    build_backend,
)
from app.search.bootstrap import (
    bootstrap_cluster,
    dedicated_template_name,
    keyring_index_name,
    shared_template_name,
)
from app.search.mappings import dedicated_index_template, shared_index_template
from app.search.query import AuditSearchFilter, UserScope
from app.search.repository import AuditRepository
from app.search.routing import UserRouter

pytestmark = pytest.mark.integration

#: The suite runs against whichever engine `SEARCH_BACKEND` names, so CI can
#: run it twice. Typed as the union rather than the port because a handful of
#: assertions deliberately reach past the port to the raw client: they check
#: what the *engine* enforces, which is the whole reason this suite exists.
SearchStore = ElasticsearchBackend | OpenSearchBackend

# A unique prefix per run, so a test run never collides with real data or with a
# previous run's leftovers.
RUN_ID = uuid.uuid4().hex[:8]
USER_A = f"itest-{RUN_ID}-a"
USER_B = f"itest-{RUN_ID}-b"
DEDICATED_USER = f"itest-{RUN_ID}-ded"


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
        "DEDICATED_USERS": DEDICATED_USER,
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
async def store(itest_settings: Settings) -> AsyncIterator[SearchStore]:
    """The configured engine, connected but not yet provisioned."""
    backend = build_backend(itest_settings)
    assert isinstance(backend, ElasticsearchBackend | OpenSearchBackend)
    if not await backend.ping():
        await backend.close()
        pytest.skip(
            f"{itest_settings.SEARCH_BACKEND.value} is not reachable at "
            f"{itest_settings.ES_HOSTS}; run `docker compose up -d`"
        )
    yield backend
    await backend.close()


@pytest.fixture(scope="module")
def router(itest_settings: Settings, store: SearchStore) -> UserRouter:
    """Built from the store, exactly as `build_container` does.

    The routing capability is the reason for the dependency: an OpenSearch data
    stream rejects a routed write, so the router must issue no routing key
    there. A router built without asking the engine would fail every write to
    the shared stream on that engine.
    """
    return UserRouter(
        shared_stream=itest_settings.SHARED_DATA_STREAM,
        index_prefix=itest_settings.INDEX_PREFIX,
        dedicated_users=itest_settings.dedicated_user_set,
        custom_routing=store.supports_custom_routing,
    )


@pytest.fixture(scope="module", autouse=True)
async def _topology(
    store: SearchStore, itest_settings: Settings, router: UserRouter
) -> AsyncIterator[None]:
    """Apply the topology once per module, and remove it afterwards."""
    await bootstrap_cluster(store, itest_settings, router)
    backend = store
    client = store.client
    yield

    # Tear down everything this run created. Audit indices are append-only in
    # production, but a test run must not leave state behind.
    #
    # Suppressed rather than logged: a stream that was never created has nothing
    # to delete, and a cleanup failure must not mask the test result.
    for name in (
        router.shared_pattern(),
        router.dedicated_stream_name(DEDICATED_USER),
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
    # The retention policy lives in a different place on each engine.
    with contextlib.suppress(Exception):
        if isinstance(backend, ElasticsearchBackend):
            await backend.client.ilm.delete_lifecycle(name=itest_settings.ILM_POLICY_NAME)
        else:
            await backend.client.transport.perform_request(
                "DELETE", f"/_plugins/_ism/policies/{itest_settings.ILM_POLICY_NAME}"
            )


@pytest.fixture
def repository(store: SearchStore, router: UserRouter, itest_settings: Settings) -> AuditRepository:
    # The configured backend, so these tests exercise the same path the service
    # uses. `store.client` stays available to the few tests that assert on what
    # the *engine* enforces.
    return AuditRepository(
        store,
        router,
        max_window_days=itest_settings.MAX_QUERY_WINDOW_DAYS,
        search_timeout=itest_settings.SEARCH_TIMEOUT,
    )


def _document(
    user_uuid: str,
    *,
    seq: int = 0,
    chain_id: str | None = None,
    action: str = "credential.issue",
    actor_id: str = "u-1",
    event_id: str | None = None,
    prev_hash: str = GENESIS_HASH,
) -> dict[str, Any]:
    """A complete, correctly chained document, as the worker would produce."""
    chain = chain_id or f"{user_uuid}:0"
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
        "user": {"uuid": user_uuid},
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


async def _refresh(store: SearchStore, router: UserRouter) -> None:
    """Make writes visible. Only needed in tests: production reads tolerate 1s."""
    await store.client.indices.refresh(
        index=f"{router.shared_pattern()},{router.dedicated_pattern()}",
        ignore_unavailable=True,
    )


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
async def test_bootstrap_creates_the_expected_topology(
    store: SearchStore, itest_settings: Settings, router: UserRouter
) -> None:
    """The topology is applied from code, so a fresh cluster cannot drift.

    The retention policy is the one piece with no common shape: ILM has phases
    keyed by name, ISM has a list of states. Both must exist and both must end
    at the same six-year ceiling, which is what this asserts per engine.
    """
    retention_days = itest_settings.RETENTION_DAYS
    if isinstance(store, ElasticsearchBackend):
        policy = await store.client.ilm.get_lifecycle(name=itest_settings.ILM_POLICY_NAME)
        phases = policy[itest_settings.ILM_POLICY_NAME]["policy"]["phases"]
        assert set(phases) == {"hot", "warm", "cold", "delete"}
        # Six years (HIPAA 164.316(b)(2)(i)).
        assert phases["delete"]["min_age"] == f"{retention_days}d"
    else:
        document = await store.client.transport.perform_request(
            "GET", f"/_plugins/_ism/policies/{itest_settings.ILM_POLICY_NAME}"
        )
        policy_body = document["policy"]
        states = {state["name"]: state for state in policy_body["states"]}
        assert set(states) == {"hot", "warm", "cold", "delete"}
        assert (
            states["cold"]["transitions"][0]["conditions"]["min_index_age"] == f"{retention_days}d"
        )
        # The policy has to claim the audit patterns, or a rolled-over backing
        # index silently ages out of retention management.
        assert policy_body["ism_template"][0]["index_patterns"]

    assert await store.client.indices.exists(index=keyring_index_name(itest_settings))
    streams = await store.client.indices.get_data_stream(name=router.shared_pattern())
    assert streams["data_streams"]


async def test_bootstrap_is_idempotent(
    store: SearchStore, itest_settings: Settings, router: UserRouter
) -> None:
    """It runs on every startup, so a second pass must be a no-op."""
    await bootstrap_cluster(store, itest_settings, router)
    await bootstrap_cluster(store, itest_settings, router)


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------
async def test_write_and_read_round_trip(
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    route = router.resolve(USER_A)
    outcome = await repository.bulk_index(
        [(route, _document(USER_A, seq=index)) for index in range(5)]
    )
    assert outcome.all_succeeded, outcome.failed
    assert outcome.succeeded == 5

    await _refresh(store, router)
    page = await repository.search(UserScope(user_uuid=USER_A), AuditSearchFilter(), size=10)
    assert len(page.events) == 5


async def test_duplicate_event_id_is_rejected_giving_exactly_once(
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    """The property that makes the at-least-once queue safe.

    A redelivered message must not produce a second copy of the event. `_id` is
    the event id and `op_type: create` refuses to overwrite, so the retry is a
    409 that the repository counts as success.
    """
    route = router.resolve(USER_A)
    event_id = f"fixed-{uuid.uuid4().hex}"
    document = _document(USER_A, seq=100, event_id=event_id)

    first = await repository.bulk_index([(route, document)])
    assert first.succeeded == 1

    # Simulate a queue redelivery of the identical event.
    second = await repository.bulk_index([(route, document)])
    assert second.all_succeeded
    assert second.succeeded == 1

    await _refresh(store, router)
    page = await repository.search(
        UserScope(user_uuid=USER_A),
        AuditSearchFilter(event_ids=(event_id,)),
        size=10,
        with_total=100,
    )
    assert len(page.events) == 1, "the event was stored twice"


async def test_unmapped_field_is_rejected_by_strict_mapping(
    repository: AuditRepository, router: UserRouter
) -> None:
    """`dynamic: strict` makes an undeclared field a loud error.

    A silently-unindexed field would be discovered during an incident, when the
    data is needed and unsearchable. The rejection routes the event to the
    dead-letter queue instead, which is alerted on.
    """
    route = router.resolve(USER_A)
    document = _document(USER_A, seq=200)
    document["totally_undeclared_field"] = "surprise"

    outcome = await repository.bulk_index([(route, document)])
    assert not outcome.all_succeeded
    reason = outcome.failed[0][1]
    assert "strict_dynamic_mapping_exception" in reason, reason
    # The worker must classify this as permanent and dead-letter it rather than
    # retrying a document that will be rejected identically forever.
    assert _is_permanent(reason)


# ---------------------------------------------------------------------------
# User isolation, enforced by the cluster
# ---------------------------------------------------------------------------
async def test_user_cannot_read_another_users_events(
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    """The isolation guarantee, verified against a real index."""
    await repository.bulk_index(
        [(router.resolve(USER_A), _document(USER_A, seq=300, actor_id="alice"))]
    )
    await repository.bulk_index(
        [(router.resolve(USER_B), _document(USER_B, seq=300, actor_id="bob"))]
    )
    await _refresh(store, router)

    a_page = await repository.search(UserScope(user_uuid=USER_A), AuditSearchFilter(), size=100)
    a_users = {event["user"]["uuid"] for event in a_page.events}
    assert a_users == {USER_A}

    # Even explicitly asking for the other user's actor returns nothing.
    leaked = await repository.search(
        UserScope(user_uuid=USER_A),
        AuditSearchFilter(actor_ids=("bob",)),
        size=100,
    )
    assert leaked.events == []


async def test_get_event_by_id_is_user_filtered(
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    """Guessing an event id must not cross a user boundary.

    This is why `get_event` is a filtered search rather than a document GET - a
    GET would return the document regardless of user.
    """
    event_id = f"cross-{uuid.uuid4().hex}"
    await repository.bulk_index(
        [(router.resolve(USER_B), _document(USER_B, seq=400, event_id=event_id))]
    )
    await _refresh(store, router)

    assert await repository.get_event(UserScope(user_uuid=USER_B), event_id)
    assert await repository.get_event(UserScope(user_uuid=USER_A), event_id) is None


async def test_a_wrong_user_document_never_reaches_the_store(
    repository: AuditRepository, router: UserRouter
) -> None:
    """The write-path guarantee, on whichever engine is configured.

    A document must land in the stream belonging to the user it names. The
    repository refuses the write itself, so the invariant does not depend on a
    field type only one engine has - and it covers the shared stream too, which
    neither engine guards.
    """
    route = router.resolve(DEDICATED_USER)
    outcome = await repository.bulk_index([(route, _document("some-other-user", seq=99))])

    assert outcome.succeeded == 0
    assert "user_uuid_mismatch" in outcome.failed[0][1]


async def test_elasticsearch_also_rejects_it_at_the_storage_layer(
    store: SearchStore, router: UserRouter
) -> None:
    """The second layer, where the engine provides one.

    A dedicated stream's backing index adopts the user uuid of its first
    document, and `constant_keyword` then refuses any document carrying a
    different one - a guarantee that holds even if the routing code is wrong.
    OpenSearch has no dependable equivalent, which is why the repository guard
    above exists; this test asserts the extra layer is still there on Elastic
    rather than silently lost.
    """
    if not isinstance(store, ElasticsearchBackend):
        pytest.skip("constant_keyword is Elasticsearch-only; the guard above covers both")

    stream = router.dedicated_stream_name(DEDICATED_USER)

    # First document establishes the constant value.
    await store.client.index(
        index=stream,
        document=_document(DEDICATED_USER, seq=0),
        op_type="create",
        refresh="wait_for",
    )

    with pytest.raises(BadRequestError) as caught:
        await store.client.index(
            index=stream,
            document=_document("some-other-user", seq=1),
            op_type="create",
            refresh="wait_for",
        )
    message = str(caught.value)
    assert "constant_keyword" in message, message


async def test_dedicated_user_reads_both_streams(
    repository: AuditRepository,
    store: SearchStore,
    router: UserRouter,
    itest_settings: Settings,
) -> None:
    """History written before promotion must stay visible.

    The setup has to be honest about how that history got there. Before the
    promotion the router knew of no dedicated users, so `resolve` returned a
    *shared* route that still carried this user's own id - which is what is
    reconstructed here. Borrowing another user's route to reach the shared
    stream would be a routing bug, and the repository's user guard refuses it.
    """
    before_promotion = UserRouter(
        shared_stream=itest_settings.SHARED_DATA_STREAM,
        index_prefix=itest_settings.INDEX_PREFIX,
        dedicated_users=frozenset(),
        custom_routing=store.supports_custom_routing,
    )
    shared_route = before_promotion.resolve(DEDICATED_USER)
    assert shared_route.write_target == router.shared_pattern()

    pre_promotion = _document(DEDICATED_USER, seq=500)
    outcome = await repository.bulk_index([(shared_route, pre_promotion)])
    assert outcome.succeeded == 1, outcome.failed
    await _refresh(store, router)

    page = await repository.search(
        UserScope(user_uuid=DEDICATED_USER), AuditSearchFilter(), size=100
    )
    ids = {event["event"]["id"] for event in page.events}
    assert pre_promotion["event"]["id"] in ids, "pre-promotion history is not visible"


# ---------------------------------------------------------------------------
# Privacy, enforced by the mapping
# ---------------------------------------------------------------------------
async def test_ciphertext_is_not_searchable(
    store: SearchStore, router: UserRouter, repository: AuditRepository
) -> None:
    """`pii_ct` is mapped `enabled: false`, so encrypted blobs cannot be queried.

    Without this, a wildcard or match_all query over the ciphertext field could
    confirm the presence of a known value.
    """
    document = _document(USER_A, seq=600)
    document["pii_ct"] = {"actor.email": "v1:nonce:ciphertextblob"}
    document["pii"] = {"encrypted": True, "key_id": "k-1", "fields": ["actor.email"]}

    outcome = await repository.bulk_index([(router.resolve(USER_A), document)])
    assert outcome.all_succeeded, outcome.failed
    await _refresh(store, router)

    # The value is retrievable from _source...
    stored = await repository.get_event(UserScope(user_uuid=USER_A), document["event"]["id"])
    assert stored is not None
    assert stored["pii_ct"]["actor.email"].startswith("v1:")

    # ...but not searchable. `enabled: false` means the subfields are unmapped,
    # so a term query matches nothing rather than confirming the value exists.
    # That is the guarantee: no oracle over encrypted content.
    response = await store.client.search(
        index=router.shared_pattern(),
        body={
            "query": {"term": {"pii_ct.actor.email": "v1:nonce:ciphertextblob"}},
            "track_total_hits": True,
        },
        ignore_unavailable=True,
    )
    assert response["hits"]["total"]["value"] == 0


async def test_pii_fields_are_absent_from_the_mapping(
    store: SearchStore, itest_settings: Settings
) -> None:
    """`actor.email` is deliberately unmapped.

    Leaving it out means a future emitter writing plaintext there is rejected by
    `dynamic: strict` rather than quietly indexing personal data.
    """
    template = shared_index_template(
        name_pattern="x",
        shards=1,
        replicas=0,
        backend=store,
        policy_name=itest_settings.ILM_POLICY_NAME,
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
    store: SearchStore,
) -> None:
    """Higher priority on the dedicated template, and a pinned user id.

    The pinned type is whatever the configured engine offers - Elastic's
    `constant_keyword`, or `keyword` where there is nothing to pin with - so
    this asserts the shape rather than one engine's field name.
    """
    shared = shared_index_template(
        name_pattern="a", shards=3, replicas=0, backend=store, policy_name="p"
    )
    dedicated = dedicated_index_template(
        name_pattern="b", shards=1, replicas=0, backend=store, policy_name="p"
    )
    assert dedicated["priority"] > shared["priority"]
    assert (
        shared["template"]["mappings"]["properties"]["user"]["properties"]["uuid"]["type"]
        == "keyword"
    )
    assert (
        dedicated["template"]["mappings"]["properties"]["user"]["properties"]["uuid"]
        == store.field_types.pinned_user_uuid
    )


# ---------------------------------------------------------------------------
# Pagination, export and integrity over real data
# ---------------------------------------------------------------------------
async def test_cursor_pagination_covers_every_event_exactly_once(
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    """`search_after` must neither skip nor repeat a row.

    Timestamps collide constantly under bulk ingest, which is why the sort
    carries a unique tiebreaker. Without it, pages would overlap.
    """
    user = f"{USER_A}-page"
    route = router.resolve(user)
    expected = {
        document["event"]["id"]: document
        for document in (_document(user, seq=index) for index in range(25))
    }
    await repository.bulk_index([(route, doc) for doc in expected.values()])
    await _refresh(store, router)

    seen: list[str] = []
    cursor: list[Any] | None = None
    for _ in range(10):  # bounded, so a paging bug fails rather than loops
        page = await repository.search(
            UserScope(user_uuid=user),
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
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    """A PIT freezes the view, so an export is a snapshot rather than a smear."""
    user = f"{USER_A}-pit"
    route = router.resolve(user)
    await repository.bulk_index([(route, _document(user, seq=index)) for index in range(10)])
    await _refresh(store, router)

    pit_id = await repository.open_pit(UserScope(user_uuid=user))
    try:
        # Documents arriving after the PIT opened must not appear in it.
        await repository.bulk_index(
            [(route, _document(user, seq=index)) for index in range(10, 20)]
        )
        await _refresh(store, router)

        collected: list[dict[str, Any]] = []
        cursor: list[Any] | None = None
        while True:
            page = await repository.search_pit(
                UserScope(user_uuid=user),
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
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    """The hash must survive storage and retrieval.

    Elasticsearch may reorder `_source` keys, so this is the test that proves
    canonical re-serialisation makes verification work on retrieved documents
    rather than only on in-memory ones.
    """
    user = f"{USER_A}-chain"
    chain_id = f"{user}:0"
    route = router.resolve(user)

    documents: list[dict[str, Any]] = []
    prev = GENESIS_HASH
    for seq in range(15):
        document = _document(user, seq=seq, chain_id=chain_id, prev_hash=prev)
        prev = document["integrity"]["hash"]
        documents.append(document)

    outcome = await repository.bulk_index([(route, doc) for doc in documents])
    assert outcome.all_succeeded, outcome.failed
    await _refresh(store, router)

    retrieved = await repository.fetch_chain_slice(
        chain_id=chain_id, user_uuid=user, start_seq=0, limit=100
    )
    assert len(retrieved) == 15

    result = verify_chain(chain_id, retrieved, expect_contiguous_from=0)
    assert result.intact, [break_.detail for break_ in result.breaks]
    assert result.verified_count == 15


async def test_aggregation_returns_buckets(
    repository: AuditRepository, store: SearchStore, router: UserRouter
) -> None:
    user = f"{USER_A}-agg"
    route = router.resolve(user)
    await repository.bulk_index(
        [
            (route, _document(user, seq=0, action="credential.issue")),
            (route, _document(user, seq=1, action="credential.issue")),
            (route, _document(user, seq=2, action="credential.revoke")),
        ]
    )
    await _refresh(store, router)

    aggregations = await repository.aggregate(
        UserScope(user_uuid=user), AuditSearchFilter(), group_by="event.action"
    )
    buckets = {bucket["key"]: bucket["doc_count"] for bucket in aggregations["by_group"]["buckets"]}
    assert buckets["credential.issue"] == 2
    assert buckets["credential.revoke"] == 1


async def test_dedicated_stream_does_not_require_routing(
    store: SearchStore, router: UserRouter
) -> None:
    """Regression guard for the `allow_custom_routing` / `_routing` coupling.

    Enabling `allow_custom_routing` on a data stream template makes
    Elasticsearch set `_routing: {required: true}` on every backing index. The
    dedicated template therefore leaves the flag off, because the router supplies
    no routing key for a dedicated user. With the flag on, every write to a
    dedicated stream fails with `routing_missing_exception` - a total ingest
    outage for exactly the highest-volume users.

    This asserts the cluster-side facts, so re-adding the flag fails here.
    """
    if not store.supports_custom_routing:
        pytest.skip("this engine has no custom routing to couple `_routing` to")

    stream = router.dedicated_stream_name(DEDICATED_USER)
    streams = await store.client.indices.get_data_stream(name=stream)
    assert streams["data_streams"][0].get("allow_custom_routing") is False

    backing = streams["data_streams"][0]["indices"][0]["index_name"]
    mapping = await store.client.indices.get_mapping(index=backing)
    assert mapping[backing]["mappings"].get("_routing") is None

    # And the shared stream, which does supply routing, has it required.
    shared = await store.client.indices.get_data_stream(name=router.shared_pattern())
    assert shared["data_streams"][0].get("allow_custom_routing") is True
