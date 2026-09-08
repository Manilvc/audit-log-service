"""Elasticsearch client construction.

Elasticsearch-specific by design - `ElasticsearchBackend` wraps what this
builds, and the integration suite uses it directly to assert on guarantees the
*engine* enforces. Everything engine-agnostic lives behind the port in
`app.search.backends`; the lifecycle of the client (info, ping, close) belongs
to the adapter, not here.

One `AsyncElasticsearch` instance per process, shared by every request. The
client owns a connection pool, so building one per request would exhaust
sockets and destroy p99 latency under load.
"""

from __future__ import annotations

from typing import Any

from elasticsearch import AsyncElasticsearch

from app.core.config import Settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def build_client(settings: Settings) -> AsyncElasticsearch:
    """Construct a hardened async client.

    Security choices:
      * API-key auth is preferred over basic auth - scoped, revocable, and no
        reusable password on the wire.
      * TLS is verified against a pinned CA when one is configured; the settings
        validator forbids disabling verification in production.
      * `max_retries` with `retry_on_timeout` covers a node restart, but writes
        still go through the durable queue, so a retry storm cannot lose events.
    """
    auth: dict[str, Any] = {}
    if settings.ES_API_KEY is not None:
        auth["api_key"] = settings.ES_API_KEY.get_secret_value()
    elif settings.ES_USERNAME and settings.ES_PASSWORD:
        auth["basic_auth"] = (
            settings.ES_USERNAME,
            settings.ES_PASSWORD.get_secret_value(),
        )

    ssl_context = settings.es_ssl_context()
    if ssl_context is not None:
        auth["ssl_context"] = ssl_context

    return AsyncElasticsearch(
        hosts=settings.ES_HOSTS,
        request_timeout=settings.ES_REQUEST_TIMEOUT,
        max_retries=settings.ES_MAX_RETRIES,
        retry_on_timeout=True,
        # Identifies this service in the cluster's own audit log, so an
        # unexpected query can be traced back to its origin.
        headers={"x-elastic-client-meta": f"{settings.SERVICE_NAME}/1.0"},
        **auth,
    )


async def ping(client: AsyncElasticsearch) -> bool:
    """Liveness check used by the readiness probe.

    Swallows the exception and returns False so the probe reports "not ready"
    rather than the endpoint returning a 500 - a distinction that matters to
    an orchestrator deciding whether to route traffic.
    """
    try:
        return bool(await client.ping())
    except Exception as exc:
        logger.warning("elasticsearch_ping_failed", error=str(exc))
        return False
