"""Event ingest, search and export endpoints.

Mounted under ``/v1/audit``. Every route requires an authenticated principal
(service API key or platform JWT) and a resolved tenant scope — the query
layer injects the tenant filter; callers cannot omit it.

Routes
------
``POST /events``
    Batch ingest (≤500). Returns **202** after durable enqueue; crypto/ES/S3
    happen in the worker, so credential flows never wait on audit I/O.
``POST /events/search`` / ``GET /events/{id}`` / ``POST /events/aggregate``
    Tenant-scoped reads. Each successful read emits an ``audit_log.*`` event
    (HIPAA 164.312(b) audit-of-the-audit).
``POST /events/export``
    Streaming NDJSON over a Point-in-Time; requires ``audit:export``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

import orjson
from fastapi import APIRouter, Body, Path, Query, status
from fastapi.responses import StreamingResponse

from app.api.deps import (
    IngestServiceDep,
    PrincipalDep,
    QueryServiceDep,
    TenantHeaderDep,
)
from app.core.exceptions import NotFound
from app.core.logging import get_logger
from app.core.responses import ORJSONResponse, success
from app.domain.enums import Scope
from app.schemas.api import (
    AggregationRequest,
    ExportRequest,
    IngestBatchIn,
    SearchRequest,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/audit", tags=["Audit Events"])


@router.post(
    "/events",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a batch of audit events",
    response_description="Counts of accepted and rejected events",
)
async def ingest_events(
    payload: Annotated[IngestBatchIn, Body()],
    principal: PrincipalDep,
    service: IngestServiceDep,
    tenant_header: TenantHeaderDep,
) -> ORJSONResponse:
    """Record audit events.

    Returns **202 Accepted**, not 201: the events are durably queued and will be
    in Elasticsearch within about a second. Reporting 201 would imply they are
    immediately searchable, which a caller might then rely on.

    Partial success is normal - one malformed event does not reject the batch.
    Check `rejected` and `errors` in the response, which reports the index of
    each failed event.
    """
    result = await service.ingest(
        payload.events,
        principal=principal,
        header_tenant_id=tenant_header,
    )
    message = (
        f"{result.accepted} event(s) accepted."
        if not result.rejected
        else f"{result.accepted} accepted, {result.rejected} rejected."
    )
    return success(
        result.model_dump(),
        message=message,
        status_code=status.HTTP_202_ACCEPTED,
    )


@router.post(
    "/events/search",
    summary="Search audit events",
)
async def search_events(
    payload: Annotated[SearchRequest, Body()],
    principal: PrincipalDep,
    service: QueryServiceDep,
    tenant_header: TenantHeaderDep,
    cross_tenant: Annotated[
        bool,
        Query(description="Query across all tenants. Requires audit:cross_tenant."),
    ] = False,
) -> ORJSONResponse:
    """Search the audit trail.

    POST rather than GET because the filter is a structured document, and because
    audit search criteria (user ids, session ids) do not belong in a URL that
    lands in access logs and browser history.

    Pagination is cursor-based: pass the `cursor` from the previous response.
    Page 500 costs the same as page 1, unlike offset pagination.

    Every search is itself recorded as an audit event, as HIPAA 164.312(b) and
    SOC 2 CC7.2 require.
    """
    result = await service.search(
        payload,
        principal=principal,
        requested_tenant_id=tenant_header,
        cross_tenant=cross_tenant,
    )
    return success(result.model_dump(), message=f"{len(result.events)} event(s) returned.")


@router.get(
    "/events/{event_id}",
    summary="Fetch one audit event",
)
async def get_event(
    event_id: Annotated[str, Path(max_length=64)],
    principal: PrincipalDep,
    service: QueryServiceDep,
    tenant_header: TenantHeaderDep,
) -> ORJSONResponse:
    """Fetch a single event by id.

    Still tenant-filtered: this is a filtered search, not a document GET, so
    guessing an event id from another tenant returns 404 rather than the record.
    """
    document = await service.get_event(
        event_id, principal=principal, requested_tenant_id=tenant_header
    )
    if document is None:
        raise NotFound("No audit event with that id is visible to you.")
    return success(document, message="Event retrieved.")


@router.post(
    "/events/aggregate",
    summary="Aggregate audit events for dashboards",
)
async def aggregate_events(
    payload: Annotated[AggregationRequest, Body()],
    principal: PrincipalDep,
    service: QueryServiceDep,
    tenant_header: TenantHeaderDep,
    cross_tenant: Annotated[bool, Query()] = False,
) -> ORJSONResponse:
    """Bucket events by a field, optionally over time.

    `group_by` is restricted to a closed allow-list; an arbitrary field name
    would let a caller aggregate on a high-cardinality keyword and exhaust
    cluster heap.
    """
    aggregations = await service.aggregate(
        payload,
        principal=principal,
        requested_tenant_id=tenant_header,
        cross_tenant=cross_tenant,
    )
    return success(aggregations, message="Aggregation complete.")


@router.post(
    "/events/export",
    summary="Stream a bulk export of audit events",
)
async def export_events(
    payload: Annotated[ExportRequest, Body()],
    principal: PrincipalDep,
    service: QueryServiceDep,
    tenant_header: TenantHeaderDep,
) -> StreamingResponse:
    """Export matching events as newline-delimited JSON.

    Streamed rather than buffered: a million-event export must not be assembled
    in memory. The response begins before the extract is complete, so the caller
    sees progress and no single request holds hundreds of MB.

    Consistency comes from a point-in-time snapshot. Without one, events arriving
    mid-export would make the extract a smear across time rather than a snapshot -
    useless as evidence. The integrity block is included by default so the
    recipient can verify the chain independently.
    """
    principal.require(Scope.EXPORT)

    async def stream() -> AsyncIterator[bytes]:
        async for document in service.export(
            payload, principal=principal, requested_tenant_id=tenant_header
        ):
            yield orjson.dumps(document) + b"\n"

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="audit-export.ndjson"',
            "X-Content-Type-Options": "nosniff",
        },
    )
