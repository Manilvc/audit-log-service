"""Idempotent cluster provisioning.

Runs on startup and from `audit-service bootstrap`. Applying the topology from
code rather than a runbook means a new environment cannot drift, and a template
change ships with the deploy that needs it.

Ordering is not incidental. The retention policy must exist before a template
references it, and the template must exist before the first document creates a
data stream - a stream created without a template gets dynamic mapping, which
would defeat `dynamic: strict` and quietly index PII.

Engine-agnostic: the provisioning steps are the same on both stores, and the
two that differ in shape - the retention policy document and the field types -
are rendered by the backend.
"""

from __future__ import annotations

from typing import Any

from app.core.config import Settings
from app.core.constants import API_KEY_INDEX_SUFFIX
from app.core.logging import get_logger
from app.search.backends import (
    RetentionPolicy,
    SearchBackend,
    SearchConflict,
    SearchNotFound,
    SearchRejected,
)
from app.search.mappings import (
    api_key_index_settings,
    dedicated_index_template,
    keyring_index_settings,
    shared_index_template,
)
from app.search.routing import UserRouter

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


def api_key_index_name(settings: Settings) -> str:
    """Stable name of the issued-API-key index for this deployment."""
    return f"{settings.INDEX_PREFIX}-{API_KEY_INDEX_SUFFIX}"


async def bootstrap_cluster(
    backend: SearchBackend,
    settings: Settings,
    router: UserRouter,
) -> dict[str, Any]:
    """Apply the retention policy, templates, keyring index and data streams.

    Returns a summary of what was applied, which the startup log records so a
    deploy leaves evidence of the topology it created.
    """
    summary: dict[str, Any] = {}

    # 1. Retention policy -----------------------------------------------------
    await backend.ensure_lifecycle_policy(
        name=settings.ILM_POLICY_NAME,
        retention=RetentionPolicy(
            retention_days=settings.RETENTION_DAYS,
            rollover_max_primary_shard_size=settings.ROLLOVER_MAX_PRIMARY_SHARD_SIZE,
            rollover_max_age=settings.ROLLOVER_MAX_AGE,
        ),
        # Both audit patterns, so an engine that attaches retention by pattern
        # covers the shared stream and every dedicated one.
        index_patterns=(router.shared_pattern(), router.dedicated_pattern()),
    )
    summary["engine"] = backend.name
    summary["lifecycle_policy"] = settings.ILM_POLICY_NAME

    # 2. Index templates ------------------------------------------------------
    shared = shared_index_template(
        name_pattern=router.shared_pattern(),
        shards=settings.SHARED_SHARD_COUNT,
        replicas=settings.INDEX_REPLICAS,
        backend=backend,
        policy_name=settings.ILM_POLICY_NAME,
    )
    shared_name = shared_template_name(settings)
    await backend.put_index_template(name=shared_name, template=shared)

    dedicated = dedicated_index_template(
        name_pattern=router.dedicated_pattern(),
        shards=settings.DEDICATED_SHARD_COUNT,
        replicas=settings.INDEX_REPLICAS,
        backend=backend,
        policy_name=settings.ILM_POLICY_NAME,
    )
    dedicated_name = dedicated_template_name(settings)
    await backend.put_index_template(name=dedicated_name, template=dedicated)
    summary["templates"] = [shared_name, dedicated_name]

    # 3. Keyring index --------------------------------------------------------
    keyring = keyring_index_name(settings)
    if not await backend.index_exists(index=keyring):
        try:
            await backend.create_index(
                index=keyring, **keyring_index_settings(replicas=settings.INDEX_REPLICAS)
            )
            logger.info("keyring_index_created", index=keyring)
        except SearchConflict:
            # Another replica won the race between the check and the create.
            logger.info("keyring_index_race_lost", index=keyring)
    summary["keyring_index"] = keyring

    # 3b. Issued API key index ------------------------------------------------
    api_keys = api_key_index_name(settings)
    if not await backend.index_exists(index=api_keys):
        try:
            await backend.create_index(
                index=api_keys, **api_key_index_settings(replicas=settings.INDEX_REPLICAS)
            )
            logger.info("api_key_index_created", index=api_keys)
        except SearchConflict:
            logger.info("api_key_index_race_lost", index=api_keys)
    summary["api_key_index"] = api_keys

    # 4. Data streams ---------------------------------------------------------
    # Created eagerly so a search before the first write returns an empty
    # result instead of an index_not_found error.
    created: list[str] = []
    for stream in (
        router.shared_pattern(),
        *(router.dedicated_stream_name(user) for user in sorted(settings.dedicated_user_set)),
    ):
        if await _ensure_data_stream(backend, stream):
            created.append(stream)
    summary["data_streams_created"] = created

    logger.info("cluster_bootstrap_complete", **summary)
    return summary


async def _ensure_data_stream(backend: SearchBackend, name: str) -> bool:
    """Create a data stream if absent. Returns True when it was created.

    The engine quirk this used to carry - a missing stream answered with 200 and
    an empty list rather than a 404 - now lives in the adapter, where it belongs:
    it is a property of Elasticsearch, not of provisioning.
    """
    if await backend.data_stream_exists(name=name):
        return False

    # A concrete index occupying the data stream's name is a dead end: the two
    # namespaces are shared, so the stream can never be created while it exists,
    # and Elasticsearch reports it as a bewildering 500 illegal_state_exception.
    # It happens when a write reaches the cluster before the index template does
    # (a bootstrap failure followed by ingest), because ES then auto-creates a
    # plain index. Detected here so the operator gets an actionable message
    # instead of having to decode a cluster-state error.
    if await backend.index_exists(index=name, include_hidden=True):
        raise RuntimeError(
            f"a concrete index named {name!r} exists, which blocks creating the "
            "data stream of the same name. This happens when audit events are "
            "written before the index template is applied. Reindex any documents "
            f"you need, then DELETE /{name} and re-run bootstrap."
        )

    try:
        await backend.create_data_stream(name=name)
        logger.info("data_stream_created", stream=name)
        return True
    except SearchConflict:
        return False
    except (SearchRejected, SearchNotFound) as exc:
        # The usual cause is a missing matching index template, which would
        # otherwise show up much later as a mapping surprise.
        logger.error("data_stream_create_failed", stream=name, error=str(exc))
        raise


async def ensure_user_stream(
    backend: SearchBackend,
    router: UserRouter,
    user_uuid: str,
) -> str:
    """Provision a dedicated stream when a user is promoted.

    Called from the admin endpoint rather than at ingest time: creating an index
    on the write path would put cluster-state latency in front of an audit
    write, and a cluster-state timeout would then drop evidence.
    """
    validated = router.validate_user_uuid(user_uuid)
    stream = router.dedicated_stream_name(validated)
    await _ensure_data_stream(backend, stream)
    return stream
