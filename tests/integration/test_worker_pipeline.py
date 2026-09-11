"""The ingest pipeline end to end: queue -> worker -> hash chain -> Elasticsearch.

    docker compose up -d elasticsearch redis
    uv run pytest -m integration

These run the real `IngestWorker` in-process against real Redis and real
Elasticsearch. That matters because the pipeline's hardest guarantee - a
gap-free, correctly linked hash chain - emerges from the interaction of atomic
Lua reservation, the partition lease, `op_type: create` deduplication and the
commit ordering. No single unit test can observe it, and a manual smoke test
cannot observe it *reliably*: chain divergence only appears under specific
interleavings.

Every test uses its own Redis key prefix and user id, so runs neither collide
with each other nor with a developer's local stack.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from redis.asyncio import Redis

from app.core.config import Settings, get_settings
from app.core.integrity import verify_chain
from app.core.security.crypto import PiiCipher
from app.queue.chain import ChainAllocator
from app.queue.stream import IngestQueue
from app.queue.worker import IngestWorker
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
from app.search.keyring import SearchKeyRing
from app.search.query import AuditSearchFilter, UserScope
from app.search.repository import AuditRepository
from app.search.routing import UserRouter

pytestmark = pytest.mark.integration

#: Same union as the end-to-end suite: the pipeline forces a refresh between
#: phases, which is an operational call on the engine rather than part of the
#: port the service uses.
SearchStore = ElasticsearchBackend | OpenSearchBackend

RUN = uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def wsettings() -> Iterator[Settings]:
    """Settings with a run-scoped index prefix and Redis key prefix."""
    overrides = {
        "INDEX_PREFIX": f"wtest-{RUN}",
        "SHARED_DATA_STREAM": f"wtest-{RUN}-shared",
        "DEDICATED_USERS": "",
        "ILM_POLICY_NAME": f"wtest-{RUN}-retention",
        "INDEX_REPLICAS": "0",
        "SHARED_SHARD_COUNT": "1",
        "STREAM_KEY_PREFIX": f"wtest:{RUN}:stream",
        # One partition keeps the test deterministic: every user lands on it,
        # so a chain break cannot be hidden by events scattering across chains.
        "STREAM_PARTITIONS": "1",
        "WORKER_BLOCK_MS": "200",
        # The archive is exercised by its own tests; disabling it here keeps this
        # suite runnable without MinIO and isolates the chain behaviour.
        "ARCHIVE_ENABLED": "false",
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
async def wes(wsettings: Settings) -> AsyncIterator[SearchStore]:
    backend = build_backend(wsettings)
    assert isinstance(backend, ElasticsearchBackend | OpenSearchBackend)
    if not await backend.ping():
        await backend.close()
        pytest.skip(
            f"{wsettings.SEARCH_BACKEND.value} is not reachable at {wsettings.ES_HOSTS}; "
            "run `docker compose up -d`"
        )
    yield backend
    await backend.close()


@pytest.fixture(scope="module")
def wrouter(wsettings: Settings, wes: SearchStore) -> UserRouter:
    """Built from the store: an OpenSearch data stream refuses a routed write."""
    return UserRouter(
        shared_stream=wsettings.SHARED_DATA_STREAM,
        index_prefix=wsettings.INDEX_PREFIX,
        dedicated_users=wsettings.dedicated_user_set,
        custom_routing=wes.supports_custom_routing,
    )


@pytest.fixture(scope="module", autouse=True)
async def _wtopology(
    wes: SearchStore, wsettings: Settings, wrouter: UserRouter
) -> AsyncIterator[None]:
    await bootstrap_cluster(wes, wsettings, wrouter)
    backend = wes
    client = wes.client
    yield

    with contextlib.suppress(Exception):
        await client.indices.delete_data_stream(name=wrouter.shared_pattern())
    with contextlib.suppress(Exception):
        await client.indices.delete(index=keyring_index_name(wsettings))
    for template in (shared_template_name(wsettings), dedicated_template_name(wsettings)):
        with contextlib.suppress(Exception):
            await client.indices.delete_index_template(name=template)
    # The retention policy lives in a different place on each engine.
    with contextlib.suppress(Exception):
        if isinstance(backend, ElasticsearchBackend):
            await backend.client.ilm.delete_lifecycle(name=wsettings.ILM_POLICY_NAME)
        else:
            await backend.client.transport.perform_request(
                "DELETE", f"/_plugins/_ism/policies/{wsettings.ILM_POLICY_NAME}"
            )


@pytest.fixture(scope="module")
async def wredis(wsettings: Settings) -> AsyncIterator[Redis]:
    client: Redis = Redis.from_url(wsettings.REDIS_URL.get_secret_value(), decode_responses=False)
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        pytest.skip("Redis is not reachable; run `docker compose up -d`")
    yield client

    # Remove every key this run created, so a rerun starts from a clean chain.
    for pattern in (f"wtest:{RUN}:*", f"audit:chain:wt-{RUN}-*"):
        async for key in client.scan_iter(match=pattern, count=500):
            await client.delete(key)
    await client.aclose()


class _Pipeline:
    """A wired worker plus the collaborators a test needs to drive it."""

    def __init__(
        self,
        *,
        settings: Settings,
        store: SearchStore,
        redis: Redis,
        router: UserRouter,
    ) -> None:
        self.settings = settings
        self.router = router
        # The raw client is kept alongside the repository: these tests force a
        # refresh between phases, which is an operational call on the engine
        # rather than part of the port the service uses.
        self.store = store
        self.repository = AuditRepository(
            store,
            router,
            max_window_days=settings.MAX_QUERY_WINDOW_DAYS,
            search_timeout=settings.SEARCH_TIMEOUT,
        )
        self.queue = IngestQueue(
            redis,
            key_prefix=settings.STREAM_KEY_PREFIX,
            consumer_group=settings.STREAM_CONSUMER_GROUP,
            partitions=settings.STREAM_PARTITIONS,
            max_len=settings.STREAM_MAX_LEN,
        )
        self.chains = ChainAllocator(redis)
        self.cipher = PiiCipher(
            settings.PII_MASTER_KEK.get_secret_value(),
            keyring=SearchKeyRing(store, index=keyring_index_name(settings)),
            enabled=settings.PII_ENCRYPTION_ENABLED,
        )
        self.worker = IngestWorker(
            settings=settings,
            redis=redis,
            queue=self.queue,
            chains=self.chains,
            repository=self.repository,
            router=router,
            cipher=self.cipher,
            archive=None,
        )

    async def publish(self, user_uuid: str, count: int, *, start: int = 0) -> list[str]:
        """Enqueue `count` events for a user, one per publish call."""
        event_ids: list[str] = []
        partition = self.router.partition_for(user_uuid, self.settings.STREAM_PARTITIONS)
        for index in range(start, start + count):
            event_id = f"{user_uuid}-evt-{index}"
            await self.queue.publish(
                partition,
                {
                    "event_id": event_id,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "user_uuid": user_uuid,
                    "action": "credential.issue",
                    "category": "credential",
                    "outcome": "success",
                    "actor": {"type": "user", "id": f"u-{index}"},
                    "target": {"type": "credential", "id": f"vc-{index}"},
                    "service_name": "wtest",
                },
            )
            event_ids.append(event_id)
        return event_ids

    async def drain(self, *, expected: int, max_wait: float = 40.0) -> int:
        """Run the worker until `expected` events are stored, or time out.

        Polls Elasticsearch rather than the queue: the queue emptying does not
        prove the documents are durable, and this suite is about what ends up in
        the ledger.
        """
        task = asyncio.create_task(self.worker.run())
        # Named `max_wait` rather than `timeout`: this is a polling budget for
        # a condition, not an asyncio cancellation timeout, and ASYNC109 flags
        # the latter naming on an async def.
        deadline = asyncio.get_running_loop().time() + max_wait
        stored = 0
        try:
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.5)
                stored = await self._count()
                if stored >= expected:
                    break
        finally:
            self.worker.stop()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        return stored

    async def _count(self) -> int:
        with contextlib.suppress(Exception):
            await self.store.client.indices.refresh(
                index=self.router.shared_pattern(), ignore_unavailable=True
            )
        page = await self.repository.search(
            UserScope(user_uuid=self._user),
            AuditSearchFilter(),
            size=200,
            with_total=1000,
        )
        return len(page.events)

    _user: str = ""

    async def fetch_chain(self, user_uuid: str) -> list[dict[str, Any]]:
        """Every stored document for a user, in chain order."""
        partition = self.router.partition_for(user_uuid, self.settings.STREAM_PARTITIONS)
        chain_id = self.router.chain_id(user_uuid, partition)
        with contextlib.suppress(Exception):
            await self.store.client.indices.refresh(
                index=self.router.shared_pattern(), ignore_unavailable=True
            )
        return await self.repository.fetch_chain_slice(
            chain_id=chain_id, user_uuid=user_uuid, start_seq=0, limit=1000
        )


@pytest.fixture
def pipeline(
    wsettings: Settings, wes: SearchStore, wredis: Redis, wrouter: UserRouter
) -> _Pipeline:
    return _Pipeline(settings=wsettings, store=wes, redis=wredis, router=wrouter)


def _chain_id_of(pipeline: _Pipeline, user_uuid: str) -> str:
    partition = pipeline.router.partition_for(user_uuid, pipeline.settings.STREAM_PARTITIONS)
    return pipeline.router.chain_id(user_uuid, partition)


# ---------------------------------------------------------------------------
# The chain must be intact, whatever the batching
# ---------------------------------------------------------------------------
async def test_single_batch_produces_an_intact_chain(pipeline: _Pipeline) -> None:
    """All events arriving before the worker starts: one large batch."""
    user = f"wt-{RUN}-single"
    pipeline._user = user
    await pipeline.publish(user, 25)

    stored = await pipeline.drain(expected=25)
    assert stored == 25, f"only {stored}/25 events reached Elasticsearch"

    documents = await pipeline.fetch_chain(user)
    result = verify_chain(_chain_id_of(pipeline, user), documents, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]
    assert result.verified_count == 25


async def test_events_arriving_while_the_worker_runs_stay_chained(
    pipeline: _Pipeline,
) -> None:
    """The realistic shape: events trickle in and are processed in many batches.

    This is the case that produced divergent `prev_hash` values before the
    commit path was fixed - each small batch reserving from a head that a
    previous batch had not yet committed.
    """
    user = f"wt-{RUN}-trickle"
    pipeline._user = user

    task = asyncio.create_task(pipeline.worker.run())
    try:
        for index in range(15):
            await pipeline.publish(user, 1, start=index)
            # Long enough that each event is read as its own batch, which is
            # exactly the interleaving that exposes a stale chain head.
            await asyncio.sleep(0.4)

        deadline = asyncio.get_running_loop().time() + 30
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.5)
            if len(await pipeline.fetch_chain(user)) >= 15:
                break
    finally:
        pipeline.worker.stop()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    documents = await pipeline.fetch_chain(user)
    assert len(documents) == 15, f"only {len(documents)}/15 events stored"

    result = verify_chain(_chain_id_of(pipeline, user), documents, expect_contiguous_from=0)
    assert result.intact, "chain diverged across batches: " + "; ".join(
        f"seq {b.seq} {b.kind}" for b in result.breaks
    )


async def test_sequence_numbers_are_contiguous_and_unique(
    pipeline: _Pipeline,
) -> None:
    """No gaps and no duplicates - what deletion/replay detection relies on."""
    user = f"wt-{RUN}-seq"
    pipeline._user = user
    await pipeline.publish(user, 20)
    await pipeline.drain(expected=20)

    documents = await pipeline.fetch_chain(user)
    seqs = [int(doc["integrity"]["seq"]) for doc in documents]
    assert seqs == list(range(len(seqs))), f"non-contiguous sequence: {seqs}"


async def test_restarting_the_worker_continues_the_chain(
    pipeline: _Pipeline,
) -> None:
    """A worker restart must not reset or fork the chain.

    The second worker instance has an empty in-process reconciliation memo, so
    this exercises the cold-start path against a chain that already has history.
    """
    user = f"wt-{RUN}-restart"
    pipeline._user = user

    await pipeline.publish(user, 8)
    assert await pipeline.drain(expected=8) == 8

    # A brand-new worker, as after a deploy.
    second = _Pipeline(
        settings=pipeline.settings,
        store=pipeline.store,
        redis=pipeline.chains._redis,
        router=pipeline.router,
    )
    second._user = user
    await second.publish(user, 8, start=8)
    await second.drain(expected=16)

    documents = await second.fetch_chain(user)
    assert len(documents) == 16
    result = verify_chain(_chain_id_of(pipeline, user), documents, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]


async def test_redelivery_does_not_duplicate_or_break_the_chain(
    pipeline: _Pipeline,
) -> None:
    """Re-publishing the same event ids must be absorbed, not duplicated.

    `op_type: create` keyed on the event id gives exactly-once storage, and the
    worker's duplicate branch must resync rather than advance the chain from an
    orphaned reservation.
    """
    user = f"wt-{RUN}-redeliver"
    pipeline._user = user

    await pipeline.publish(user, 6)
    assert await pipeline.drain(expected=6) == 6
    first = await pipeline.fetch_chain(user)
    hashes_before = {d["event"]["id"]: d["integrity"]["hash"] for d in first}

    # Exactly the same event ids again - a queue replay.
    await pipeline.publish(user, 6)
    await pipeline.drain(expected=6)

    after = await pipeline.fetch_chain(user)
    assert len(after) == 6, f"redelivery created duplicates: {len(after)} documents"
    # The stored documents are untouched: same ids, same hashes.
    assert {d["event"]["id"]: d["integrity"]["hash"] for d in after} == hashes_before

    result = verify_chain(_chain_id_of(pipeline, user), after, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]


async def test_pii_is_encrypted_by_the_worker(pipeline: _Pipeline) -> None:
    """The worker, not the API, performs field-level encryption."""
    user = f"wt-{RUN}-pii"
    pipeline._user = user
    partition = pipeline.router.partition_for(user, pipeline.settings.STREAM_PARTITIONS)
    await pipeline.queue.publish(
        partition,
        {
            "event_id": f"{user}-evt-0",
            "timestamp": datetime.now(UTC).isoformat(),
            "user_uuid": user,
            "action": "user.login",
            "category": "authentication",
            "outcome": "success",
            "actor": {"type": "user", "id": "u-1", "email": "alice@example.com"},
            "source": {"ip": "203.0.113.9", "country_code": "IN"},
            "service_name": "wtest",
        },
    )
    await pipeline.drain(expected=1)

    documents = await pipeline.fetch_chain(user)
    assert len(documents) == 1
    stored = documents[0]

    # Plaintext is gone from the indexed fields...
    assert "email" not in stored.get("actor", {})
    assert "ip" not in stored.get("source", {})
    assert "alice@example.com" not in str(stored)
    # ...and present as ciphertext with a shreddable key id.
    assert set(stored["pii_ct"]) == {"actor.email", "source.ip"}
    assert stored["pii"]["encrypted"] is True
    assert stored["pii"]["key_id"]
    # The non-identifying network prefix survives for analytics.
    assert stored["source"]["ip_prefix"] == "203.0.113.0/24"


async def test_malformed_event_is_dead_lettered_not_chained(
    pipeline: _Pipeline,
) -> None:
    """A bad payload must not consume a chain position or block the partition."""
    user = f"wt-{RUN}-dlq"
    pipeline._user = user
    partition = pipeline.router.partition_for(user, pipeline.settings.STREAM_PARTITIONS)

    # Missing the required `action`, so domain validation rejects it.
    await pipeline.queue.publish(
        partition,
        {
            "event_id": f"{user}-bad",
            "timestamp": datetime.now(UTC).isoformat(),
            "user_uuid": user,
            "category": "credential",
        },
    )
    await pipeline.publish(user, 3)
    await pipeline.drain(expected=3)

    documents = await pipeline.fetch_chain(user)
    assert len(documents) == 3, "the malformed event should not have been stored"
    result = verify_chain(_chain_id_of(pipeline, user), documents, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]

    depth = await pipeline.queue.depth()
    assert depth["dead_letter_total"] >= 1, "the malformed event was not dead-lettered"
