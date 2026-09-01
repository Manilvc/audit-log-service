"""Operational endpoints: health probes, metrics and tenant administration.

Probes and ``/metrics`` are mounted *outside* the versioned ``/v1`` prefix so
orchestrator config does not churn with API versions. ``/metrics`` is
unauthenticated and must stay unreachable from the public internet — see
``deploy/nginx/audit.conf``.

``GET /health/live`` / ``/health/ready`` / ``/health``
    Liveness (process only), readiness (Redis required; ES optional because
    the queue absorbs writes), and a full dependency report for dashboards.
``GET /metrics``
    Prometheus scrape endpoint (process defaults + ingest pipeline counters).
``POST /v1/audit/admin/tenants/{id}/dedicate`` (``audit:admin``)
    Provision a dedicated data stream for a high-volume or contractually
    isolated tenant. Non-destructive: reads still cover the shared stream.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Path, Request, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.deps import PrincipalDep, SettingsDep
from app.core.logging import get_logger
from app.core.metrics import QUEUE_DEAD_LETTER_TOTAL, QUEUE_DEPTH
from app.core.responses import ORJSONResponse, success
from app.domain.enums import Scope
from app.search.bootstrap import ensure_tenant_stream
from app.search.client import cluster_info, ping

logger = get_logger(__name__)

# Probes and metrics are mounted OUTSIDE the versioned prefix: an
# orchestrator's probe configuration should not have to change when the API
# version does.
router = APIRouter(tags=["Operations"])

# Administrative routes are versioned like the rest of the API.
admin_router = APIRouter(prefix="/audit/admin", tags=["Operations"])


@router.get("/health/live", summary="Liveness probe", include_in_schema=False)
async def liveness() -> ORJSONResponse:
    """Is the process running?

    Deliberately checks nothing external. A liveness probe that fails when
    Elasticsearch is briefly unavailable would make the orchestrator restart
    every replica during an ES upgrade, turning a degraded read path into a total
    outage.
    """
    return success({"status": "alive"}, message="Service is alive.")


@router.get("/health/ready", summary="Readiness probe", include_in_schema=False)
async def readiness(request: Request, response: Response) -> Any:
    """Can the service serve traffic?

    Readiness *does* check dependencies, because a replica that cannot reach
    Redis cannot accept an audit event and should be taken out of rotation.

    Elasticsearch being down is reported but does **not** fail readiness: the
    queue absorbs writes during an ES outage, which is the entire reason it
    exists. Failing readiness there would stop ingest and lose the events the
    design is meant to protect.
    """
    container = request.app.state.container
    checks: dict[str, object] = {}

    try:
        await container.redis.ping()
        checks["redis"] = "ok"
        redis_ok = True
    except Exception as exc:
        checks["redis"] = f"unavailable: {exc}"
        redis_ok = False

    es_ok = await ping(container.es)
    checks["elasticsearch"] = "ok" if es_ok else "unavailable (writes still buffered)"

    if not redis_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "fail", "data": checks, "message": "Ingest buffer unavailable."}

    return success(checks, message="Ready.")


@router.get("/health", summary="Detailed health", include_in_schema=False)
async def health(request: Request, settings: SettingsDep) -> ORJSONResponse:
    """Full dependency and topology report, for dashboards and on-call.

    Queue depth is the leading indicator worth watching: it rises before
    anything user-visible breaks, and a non-zero `dead_letter_total` means audit
    events were permanently rejected and need human attention.
    """
    container = request.app.state.container
    report: dict[str, object] = {
        "service": settings.SERVICE_NAME,
        "environment": settings.ENVIRONMENT.value,
    }

    try:
        report["elasticsearch"] = await cluster_info(container.es)
    except Exception as exc:
        report["elasticsearch"] = {"error": str(exc)}

    try:
        report["queue"] = await container.queue.depth()
        depth = report["queue"]
        if isinstance(depth, dict):
            QUEUE_DEPTH.set(int(depth.get("total", 0)))
            QUEUE_DEAD_LETTER_TOTAL.set(int(depth.get("dead_letter_total", 0)))
    except Exception as exc:
        report["queue"] = {"error": str(exc)}

    report["archive"] = {
        "enabled": container.archive.enabled,
        "mode": settings.OBJECT_LOCK_MODE,
        "retain_days": settings.OBJECT_LOCK_RETAIN_DAYS,
    }
    report["pii_encryption"] = container.cipher.enabled
    report["retention_days"] = settings.RETENTION_DAYS
    report["dedicated_tenants"] = len(settings.dedicated_tenant_set)

    return success(report, message="Health report.")


@router.get("/metrics", summary="Prometheus metrics", include_in_schema=False)
async def metrics() -> Response:
    """Prometheus scrape endpoint.

    Unauthenticated, so it must stay unreachable from outside the cluster - the
    nginx config in `deploy/` denies it externally. It exposes no audit content,
    only counters.
    """
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@admin_router.post(
    "/tenants/{tenant_id}/dedicate",
    summary="Promote a tenant to a dedicated data stream",
)
async def dedicate_tenant(
    tenant_id: Annotated[str, Path(max_length=64)],
    request: Request,
    principal: PrincipalDep,
    settings: SettingsDep,
) -> ORJSONResponse:
    """Provision a dedicated data stream for a high-volume tenant.

    Creating the stream is done here rather than lazily at ingest time on
    purpose: an index creation puts cluster-state latency in front of an audit
    write, and a cluster-state timeout would drop evidence.

    This only creates the stream. Routing follows `DEDICATED_TENANTS`, so the
    tenant must also be added to that setting and the service restarted -
    deliberately a config change, so index topology is reviewable in version
    control rather than mutable at runtime. Events already in the shared stream
    stay readable; the router reads both.
    """
    principal.require(Scope.ADMIN)
    container = request.app.state.container
    stream = await ensure_tenant_stream(container.es, container.router, tenant_id)

    already_routed = tenant_id in settings.dedicated_tenant_set
    logger.warning(
        "tenant_dedicated_stream_provisioned",
        tenant_id=tenant_id,
        stream=stream,
        routing_active=already_routed,
        by=principal.audit_identity,
    )
    return success(
        {
            "tenant_id": tenant_id,
            "stream": stream,
            "routing_active": already_routed,
        },
        message=(
            "Dedicated stream ready and routing is active."
            if already_routed
            else (
                f"Stream {stream} created. Add {tenant_id} to DEDICATED_TENANTS "
                "and restart the service to route writes to it."
            )
        ),
    )
