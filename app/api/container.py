"""Composition root.

Every collaborator is constructed here and nowhere else, so the dependency graph
is readable in one place and the whole service can be assembled against fakes in
a test without patching module globals.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from elasticsearch import AsyncElasticsearch
from redis.asyncio import Redis

from app.archive.s3_worm import WormArchive
from app.core.config import Settings
from app.core.logging import get_logger
from app.core.security.auth import Authenticator
from app.core.security.crypto import PiiCipher
from app.queue.chain import ChainAllocator
from app.queue.stream import IngestQueue
from app.search.bootstrap import keyring_index_name
from app.search.client import build_client
from app.search.keyring import ElasticKeyRing
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter
from app.services.compliance_service import ErasureService, IntegrityService
from app.services.ingest_service import IngestService
from app.services.query_service import QueryService

logger = get_logger(__name__)


@dataclass(slots=True)
class ServiceContainer:
    """Everything the API and the worker need, wired together."""

    settings: Settings
    es: AsyncElasticsearch
    redis: Redis
    router: TenantRouter
    repository: AuditRepository
    keyring: ElasticKeyRing
    cipher: PiiCipher
    queue: IngestQueue
    chains: ChainAllocator
    archive: WormArchive
    authenticator: Authenticator
    ingest: IngestService
    query: QueryService
    integrity: IntegrityService
    erasure: ErasureService

    async def aclose(self) -> None:
        """Release every pooled resource on shutdown."""
        try:
            await self.es.close()
        except Exception as exc:
            logger.warning("es_close_failed", error=str(exc))
        try:
            await self.redis.aclose()
        except Exception as exc:
            logger.warning("redis_close_failed", error=str(exc))


def build_container(settings: Settings) -> ServiceContainer:
    """Construct the service graph.

    No I/O happens here - clients are created but not connected, so this is safe
    to call before the event loop is running and a dependency being down does not
    prevent the process from starting and reporting itself unhealthy.
    """
    es = build_client(settings)
    redis: Redis = Redis.from_url(
        settings.REDIS_URL.get_secret_value(),
        # Bytes rather than str: stream payloads are JSON that orjson parses
        # directly from bytes, so decoding to str would be wasted work.
        decode_responses=False,
        health_check_interval=30,
        socket_keepalive=True,
        # Bounded so a Redis stall cannot exhaust the worker's task pool.
        max_connections=64,
    )

    router = TenantRouter(
        shared_stream=settings.SHARED_DATA_STREAM,
        index_prefix=settings.INDEX_PREFIX,
        dedicated_tenants=settings.dedicated_tenant_set,
    )
    repository = AuditRepository(
        es,
        router,
        max_window_days=settings.MAX_QUERY_WINDOW_DAYS,
        search_timeout=settings.SEARCH_TIMEOUT,
    )
    keyring = ElasticKeyRing(es, index=keyring_index_name(settings))
    cipher = PiiCipher(
        settings.PII_MASTER_KEK.get_secret_value(),
        keyring=keyring,
        kek_version=settings.PII_KEK_VERSION,
        enabled=settings.PII_ENCRYPTION_ENABLED,
    )
    queue = IngestQueue(
        redis,
        key_prefix=settings.STREAM_KEY_PREFIX,
        consumer_group=settings.STREAM_CONSUMER_GROUP,
        partitions=settings.STREAM_PARTITIONS,
        max_len=settings.STREAM_MAX_LEN,
    )
    chains = ChainAllocator(redis)
    archive = WormArchive(settings)

    return ServiceContainer(
        settings=settings,
        es=es,
        redis=redis,
        router=router,
        repository=repository,
        keyring=keyring,
        cipher=cipher,
        queue=queue,
        chains=chains,
        archive=archive,
        authenticator=Authenticator(settings),
        ingest=IngestService(settings=settings, queue=queue, router=router),
        query=QueryService(
            settings=settings,
            repository=repository,
            router=router,
            cipher=cipher,
            queue=queue,
        ),
        integrity=IntegrityService(
            settings=settings,
            repository=repository,
            router=router,
            archive=archive,
        ),
        erasure=ErasureService(
            settings=settings,
            repository=repository,
            router=router,
            cipher=cipher,
            keyring=keyring,
            queue=queue,
        ),
    )


def build_worker(container: ServiceContainer) -> Any:
    """Construct the ingest worker from an existing container."""
    from app.queue.worker import IngestWorker

    return IngestWorker(
        settings=container.settings,
        redis=container.redis,
        queue=container.queue,
        chains=container.chains,
        repository=container.repository,
        router=container.router,
        cipher=container.cipher,
        archive=container.archive,
    )
