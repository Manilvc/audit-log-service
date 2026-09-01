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

Every test uses its own Redis key prefix and tenant id, so runs neither collide
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
from elasticsearch import AsyncElasticsearch
from redis.asyncio import Redis

from app.core.config import Settings, get_settings
from app.core.integrity import verify_chain
from app.core.security.crypto import PiiCipher
from app.queue.chain import ChainAllocator
from app.queue.stream import IngestQueue
from app.queue.worker import IngestWorker
from app.search.bootstrap import (
    bootstrap_cluster,
    dedicated_template_name,
    keyring_index_name,
    shared_template_name,
)
from app.search.client import build_client, ping
from app.search.keyring import ElasticKeyRing
from app.search.query import AuditSearchFilter, TenantScope
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter

pytestmark = pytest.mark.integration

RUN = uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def wsettings() -> Iterator[Settings]:
    """Settings with a run-scoped index prefix and Redis key prefix."""
    overrides = {
        "INDEX_PREFIX": f"wtest-{RUN}",
        "SHARED_DATA_STREAM": f"wtest-{RUN}-shared",
        "DEDICATED_TENANTS": "",
        "ILM_POLICY_NAME": f"wtest-{RUN}-retention",
        "INDEX_REPLICAS": "0",
        "SHARED_SHARD_COUNT": "1",
        "STREAM_KEY_PREFIX": f"wtest:{RUN}:stream",
        # One partition keeps the test deterministic: every tenant lands on it,
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
def wrouter(wsettings: Settings) -> TenantRouter:
    return TenantRouter(
        shared_stream=wsettings.SHARED_DATA_STREAM,
        index_prefix=wsettings.INDEX_PREFIX,
        dedicated_tenants=wsettings.dedicated_tenant_set,
    )


@pytest.fixture(scope="module")
async def wes(wsettings: Settings, wrouter: TenantRouter) -> AsyncIterator[AsyncElasticsearch]:
    client = build_client(wsettings)
    if not await ping(client):
        await client.close()
        pytest.skip("Elasticsearch is not reachable; run `docker compose up -d`")
    await bootstrap_cluster(client, wsettings, wrouter)
    yield client

    with contextlib.suppress(Exception):
        await client.indices.delete_data_stream(name=wrouter.shared_pattern())
    with contextlib.suppress(Exception):
        await client.indices.delete(index=keyring_index_name(wsettings))
    for template in (shared_template_name(wsettings), dedicated_template_name(wsettings)):
        with contextlib.suppress(Exception):
            await client.indices.delete_index_template(name=template)
    with contextlib.suppress(Exception):
        await client.ilm.delete_lifecycle(name=wsettings.ILM_POLICY_NAME)
    await client.close()


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
        es: AsyncElasticsearch,
        redis: Redis,
        router: TenantRouter,
    ) -> None:
        self.settings = settings
        self.router = router
        self.repository = AuditRepository(
            es,
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
            keyring=ElasticKeyRing(es, index=keyring_index_name(settings)),
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

    async def publish(self, tenant_id: str, count: int, *, start: int = 0) -> list[str]:
        """Enqueue `count` events for a tenant, one per publish call."""
        event_ids: list[str] = []
        partition = self.router.partition_for(tenant_id, self.settings.STREAM_PARTITIONS)
        for index in range(start, start + count):
            event_id = f"{tenant_id}-evt-{index}"
            await self.queue.publish(
                partition,
                {
                    "event_id": event_id,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "tenant_id": tenant_id,
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
            await self.repository._client.indices.refresh(
                index=self.router.shared_pattern(), ignore_unavailable=True
            )
        page = await self.repository.search(
            TenantScope(tenant_id=self._tenant),
            AuditSearchFilter(),
            size=200,
            with_total=1000,
        )
        return len(page.events)

    _tenant: str = ""

    async def fetch_chain(self, tenant_id: str) -> list[dict[str, Any]]:
        """Every stored document for a tenant, in chain order."""
        partition = self.router.partition_for(tenant_id, self.settings.STREAM_PARTITIONS)
        chain_id = self.router.chain_id(tenant_id, partition)
        with contextlib.suppress(Exception):
            await self.repository._client.indices.refresh(
                index=self.router.shared_pattern(), ignore_unavailable=True
            )
        return await self.repository.fetch_chain_slice(
            chain_id=chain_id, tenant_id=tenant_id, start_seq=0, limit=1000
        )


@pytest.fixture
def pipeline(
    wsettings: Settings, wes: AsyncElasticsearch, wredis: Redis, wrouter: TenantRouter
) -> _Pipeline:
    return _Pipeline(settings=wsettings, es=wes, redis=wredis, router=wrouter)


def _chain_id_of(pipeline: _Pipeline, tenant_id: str) -> str:
    partition = pipeline.router.partition_for(tenant_id, pipeline.settings.STREAM_PARTITIONS)
    return pipeline.router.chain_id(tenant_id, partition)


# ---------------------------------------------------------------------------
# The chain must be intact, whatever the batching
# ---------------------------------------------------------------------------
async def test_single_batch_produces_an_intact_chain(pipeline: _Pipeline) -> None:
    """All events arriving before the worker starts: one large batch."""
    tenant = f"wt-{RUN}-single"
    pipeline._tenant = tenant
    await pipeline.publish(tenant, 25)

    stored = await pipeline.drain(expected=25)
    assert stored == 25, f"only {stored}/25 events reached Elasticsearch"

    documents = await pipeline.fetch_chain(tenant)
    result = verify_chain(_chain_id_of(pipeline, tenant), documents, expect_contiguous_from=0)
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
    tenant = f"wt-{RUN}-trickle"
    pipeline._tenant = tenant

    task = asyncio.create_task(pipeline.worker.run())
    try:
        for index in range(15):
            await pipeline.publish(tenant, 1, start=index)
            # Long enough that each event is read as its own batch, which is
            # exactly the interleaving that exposes a stale chain head.
            await asyncio.sleep(0.4)

        deadline = asyncio.get_running_loop().time() + 30
        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(0.5)
            if len(await pipeline.fetch_chain(tenant)) >= 15:
                break
    finally:
        pipeline.worker.stop()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task

    documents = await pipeline.fetch_chain(tenant)
    assert len(documents) == 15, f"only {len(documents)}/15 events stored"

    result = verify_chain(_chain_id_of(pipeline, tenant), documents, expect_contiguous_from=0)
    assert result.intact, "chain diverged across batches: " + "; ".join(
        f"seq {b.seq} {b.kind}" for b in result.breaks
    )


async def test_sequence_numbers_are_contiguous_and_unique(
    pipeline: _Pipeline,
) -> None:
    """No gaps and no duplicates - what deletion/replay detection relies on."""
    tenant = f"wt-{RUN}-seq"
    pipeline._tenant = tenant
    await pipeline.publish(tenant, 20)
    await pipeline.drain(expected=20)

    documents = await pipeline.fetch_chain(tenant)
    seqs = [int(doc["integrity"]["seq"]) for doc in documents]
    assert seqs == list(range(len(seqs))), f"non-contiguous sequence: {seqs}"


async def test_restarting_the_worker_continues_the_chain(
    pipeline: _Pipeline,
) -> None:
    """A worker restart must not reset or fork the chain.

    The second worker instance has an empty in-process reconciliation memo, so
    this exercises the cold-start path against a chain that already has history.
    """
    tenant = f"wt-{RUN}-restart"
    pipeline._tenant = tenant

    await pipeline.publish(tenant, 8)
    assert await pipeline.drain(expected=8) == 8

    # A brand-new worker, as after a deploy.
    second = _Pipeline(
        settings=pipeline.settings,
        es=pipeline.repository._client,
        redis=pipeline.chains._redis,
        router=pipeline.router,
    )
    second._tenant = tenant
    await second.publish(tenant, 8, start=8)
    await second.drain(expected=16)

    documents = await second.fetch_chain(tenant)
    assert len(documents) == 16
    result = verify_chain(_chain_id_of(pipeline, tenant), documents, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]


async def test_redelivery_does_not_duplicate_or_break_the_chain(
    pipeline: _Pipeline,
) -> None:
    """Re-publishing the same event ids must be absorbed, not duplicated.

    `op_type: create` keyed on the event id gives exactly-once storage, and the
    worker's duplicate branch must resync rather than advance the chain from an
    orphaned reservation.
    """
    tenant = f"wt-{RUN}-redeliver"
    pipeline._tenant = tenant

    await pipeline.publish(tenant, 6)
    assert await pipeline.drain(expected=6) == 6
    first = await pipeline.fetch_chain(tenant)
    hashes_before = {d["event"]["id"]: d["integrity"]["hash"] for d in first}

    # Exactly the same event ids again - a queue replay.
    await pipeline.publish(tenant, 6)
    await pipeline.drain(expected=6)

    after = await pipeline.fetch_chain(tenant)
    assert len(after) == 6, f"redelivery created duplicates: {len(after)} documents"
    # The stored documents are untouched: same ids, same hashes.
    assert {d["event"]["id"]: d["integrity"]["hash"] for d in after} == hashes_before

    result = verify_chain(_chain_id_of(pipeline, tenant), after, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]


async def test_pii_is_encrypted_by_the_worker(pipeline: _Pipeline) -> None:
    """The worker, not the API, performs field-level encryption."""
    tenant = f"wt-{RUN}-pii"
    pipeline._tenant = tenant
    partition = pipeline.router.partition_for(tenant, pipeline.settings.STREAM_PARTITIONS)
    await pipeline.queue.publish(
        partition,
        {
            "event_id": f"{tenant}-evt-0",
            "timestamp": datetime.now(UTC).isoformat(),
            "tenant_id": tenant,
            "action": "user.login",
            "category": "authentication",
            "outcome": "success",
            "actor": {"type": "user", "id": "u-1", "email": "alice@example.com"},
            "source": {"ip": "203.0.113.9", "country_code": "IN"},
            "service_name": "wtest",
        },
    )
    await pipeline.drain(expected=1)

    documents = await pipeline.fetch_chain(tenant)
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
    tenant = f"wt-{RUN}-dlq"
    pipeline._tenant = tenant
    partition = pipeline.router.partition_for(tenant, pipeline.settings.STREAM_PARTITIONS)

    # Missing the required `action`, so domain validation rejects it.
    await pipeline.queue.publish(
        partition,
        {
            "event_id": f"{tenant}-bad",
            "timestamp": datetime.now(UTC).isoformat(),
            "tenant_id": tenant,
            "category": "credential",
        },
    )
    await pipeline.publish(tenant, 3)
    await pipeline.drain(expected=3)

    documents = await pipeline.fetch_chain(tenant)
    assert len(documents) == 3, "the malformed event should not have been stored"
    result = verify_chain(_chain_id_of(pipeline, tenant), documents, expect_contiguous_from=0)
    assert result.intact, [b.detail for b in result.breaks]

    depth = await pipeline.queue.depth()
    assert depth["dead_letter_total"] >= 1, "the malformed event was not dead-lettered"
