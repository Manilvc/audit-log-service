"""Idempotent cluster provisioning.

Runs on startup and from `audit-service bootstrap`. Applying the topology from
code rather than a runbook means a new environment cannot drift, and a template
change ships with the deploy that needs it.

Ordering is not incidental. The ILM policy must exist before a template
references it, and the template must exist before the first document creates a
data stream - a stream created without a template gets dynamic mapping, which
would defeat `dynamic: strict` and quietly index PII.
"""

from __future__ import annotations

from typing import Any

from elasticsearch import AsyncElasticsearch, BadRequestError, NotFoundError

from app.core.config import Settings
from app.core.logging import get_logger
from app.search.mappings import (
    dedicated_index_template,
    ilm_policy,
    keyring_index_settings,
    shared_index_template,
)
from app.search.routing import TenantRouter

logger = get_logger(__name__)

# Template names are derived from INDEX_PREFIX rather than hardcoded. Two
# deployments sharing a cluster - staging alongside an integration test run, say -
# have different prefixes but would otherwise fight over the same two template
# names, and re-applying a template whose index pattern no longer matches an
# existing data stream is rejected outright:
#   "composable template [...] would cause data streams [...] to no longer
#    match a data stream template"
_TEMPLATE_SUFFIX_SHARED = "shared"
_TEMPLATE_SUFFIX_DEDICATED = "dedicated"


def shared_template_name(settings: Settings) -> str:
    """Name of the shared-stream index template for this deployment."""
    return f"{settings.INDEX_PREFIX}-{_TEMPLATE_SUFFIX_SHARED}"


def dedicated_template_name(settings: Settings) -> str:
    """Name of the dedicated-stream index template for this deployment."""
    return f"{settings.INDEX_PREFIX}-{_TEMPLATE_SUFFIX_DEDICATED}"


def keyring_index_name(settings: Settings) -> str:
    """Stable name of the wrapped-DEK keyring index for this deployment."""
    return f"{settings.INDEX_PREFIX}-keyring-v1"


async def bootstrap_cluster(
    client: AsyncElasticsearch,
    settings: Settings,
    router: TenantRouter,
) -> dict[str, Any]:
    """Apply ILM policy, index templates, the keyring index and data streams.

    Returns a summary of what was applied, which the startup log records so a
    deploy leaves evidence of the topology it created.
    """
    summary: dict[str, Any] = {}

    # 1. ILM policy -----------------------------------------------------------
    policy = ilm_policy(
        retention_days=settings.RETENTION_DAYS,
        rollover_max_primary_shard_size=settings.ROLLOVER_MAX_PRIMARY_SHARD_SIZE,
        rollover_max_age=settings.ROLLOVER_MAX_AGE,
    )
    await client.ilm.put_lifecycle(name=settings.ILM_POLICY_NAME, policy=policy["policy"])
    summary["ilm_policy"] = settings.ILM_POLICY_NAME

    # 2. Index templates ------------------------------------------------------
    shared = shared_index_template(
        name_pattern=router.shared_pattern(),
        shards=settings.SHARED_SHARD_COUNT,
        replicas=settings.INDEX_REPLICAS,
        ilm_policy_name=settings.ILM_POLICY_NAME,
    )
    shared_name = shared_template_name(settings)
    await client.indices.put_index_template(name=shared_name, **shared)

    dedicated = dedicated_index_template(
        name_pattern=router.dedicated_pattern(),
        shards=settings.DEDICATED_SHARD_COUNT,
        replicas=settings.INDEX_REPLICAS,
        ilm_policy_name=settings.ILM_POLICY_NAME,
    )
    dedicated_name = dedicated_template_name(settings)
    await client.indices.put_index_template(name=dedicated_name, **dedicated)
    summary["templates"] = [shared_name, dedicated_name]

    # 3. Keyring index --------------------------------------------------------
    keyring = keyring_index_name(settings)
    if not await client.indices.exists(index=keyring):
        try:
            await client.indices.create(
                index=keyring, **keyring_index_settings(replicas=settings.INDEX_REPLICAS)
            )
            logger.info("keyring_index_created", index=keyring)
        except BadRequestError as exc:
            # Another replica won the race between exists() and create().
            if "resource_already_exists_exception" not in str(exc):
                raise
    summary["keyring_index"] = keyring

    # 4. Data streams ---------------------------------------------------------
    # Created eagerly so a search before the first write returns an empty
    # result instead of an index_not_found error.
    created: list[str] = []
    for stream in (
        router.shared_pattern(),
        *(router.dedicated_stream_name(tenant) for tenant in sorted(settings.dedicated_tenant_set)),
    ):
        if await _ensure_data_stream(client, stream):
            created.append(stream)
    summary["data_streams_created"] = created

    logger.info("cluster_bootstrap_complete", **summary)
    return summary


async def _ensure_data_stream(client: AsyncElasticsearch, name: str) -> bool:
    """Create a data stream if absent. Returns True when it was created.

    The existence check inspects the response *body*, not just the status code.
    Elasticsearch 9.x answers ``GET /_data_stream/<name>`` for a stream that does
    not exist with **HTTP 200 and an empty ``data_streams`` list**, not a 404.
    Relying on ``NotFoundError`` alone therefore reports every missing stream as
    already present, and nothing is ever created - which defeats the point of
    pre-provisioning a tenant's stream off the write path. The NotFoundError
    branch is kept because older versions do return 404.
    """
    try:
        existing = await client.indices.get_data_stream(name=name)
        if existing.get("data_streams"):
            return False
    except NotFoundError:
        pass

    # A concrete index occupying the data stream's name is a dead end: the two
    # namespaces are shared, so the stream can never be created while it exists,
    # and Elasticsearch reports it as a bewildering 500 illegal_state_exception.
    # It happens when a write reaches the cluster before the index template does
    # (a bootstrap failure followed by ingest), because ES then auto-creates a
    # plain index. Detected here so the operator gets an actionable message
    # instead of having to decode a cluster-state error.
    if await client.indices.exists(index=name, expand_wildcards="all"):
        raise RuntimeError(
            f"a concrete index named {name!r} exists, which blocks creating the "
            "data stream of the same name. This happens when audit events are "
            "written before the index template is applied. Reindex any documents "
            f"you need, then DELETE /{name} and re-run bootstrap."
        )

    try:
        await client.indices.create_data_stream(name=name)
        logger.info("data_stream_created", stream=name)
        return True
    except BadRequestError as exc:
        message = str(exc)
        if "resource_already_exists_exception" in message:
            return False
        # The usual cause is a missing matching index template, which would
        # otherwise show up much later as a mapping surprise.
        logger.error("data_stream_create_failed", stream=name, error=message)
        raise


async def ensure_tenant_stream(
    client: AsyncElasticsearch,
    router: TenantRouter,
    tenant_id: str,
) -> str:
    """Provision a dedicated stream when a tenant is promoted.

    Called from the admin endpoint rather than at ingest time: creating an index
    on the write path would put cluster-state latency in front of an audit
    write, and a cluster-state timeout would then drop evidence.
    """
    validated = router.validate_tenant_id(tenant_id)
    stream = router.dedicated_stream_name(validated)
    await _ensure_data_stream(client, stream)
    return stream
