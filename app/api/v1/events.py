"""Event ingest, search and export endpoints.

Mounted under ``/v1/audit``. Every route requires a valid ``x-api-key`` and a
user named in ``x-audit-user-uuid`` — the query layer injects the user
filter from that header; callers cannot omit it.

Routes
------
``POST /events``
    Batch ingest (≤500). Returns **202** after durable enqueue; crypto/ES/S3
    happen in the worker, so credential flows never wait on audit I/O.
``GET /events``
    The console listing: one page of display-ready rows for the audit log
    table and its detail drawer. Filter chips, cursor pagination, and a
    per-row hash self-check.
``POST /events/search`` / ``GET /events/{id}`` / ``POST /events/aggregate``
    User-scoped reads over canonical ECS documents. Each successful read emits
    an ``audit_log.*`` event (HIPAA 164.312(b) audit-of-the-audit).
``POST /events/export``
    Streaming NDJSON over a Point-in-Time; requires ``audit:export``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated

import orjson
from fastapi import APIRouter, Body, Path, Query, status
from fastapi.responses import StreamingResponse

from app.api.deps import (
    IngestServiceDep,
    IssuerHeaderDep,
    PrincipalDep,
    QueryServiceDep,
    UserUuidDep,
    UserUuidHeaderDep,
)
from app.core.constants import DEFAULT_LISTING_PAGE_SIZE, MAX_CURSOR_LENGTH
from app.core.exceptions import NotFound
from app.core.logging import get_logger
from app.core.responses import ORJSONResponse, success
from app.domain.display import FilterPreset
from app.domain.enums import Outcome, Scope, Severity
from app.schemas.api import (
    AggregationRequest,
    ExportRequest,
    IngestBatchIn,
    SearchRequest,
    decode_cursor,
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
    user_uuid_header: UserUuidDep,
    issuer_header: IssuerHeaderDep,
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
        header_user_uuid=user_uuid_header,
        header_issuer_id=issuer_header,
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


@router.get(
    "/events",
    summary="List audit events for the console",
    response_description="One page of display-ready audit log rows",
)
async def list_events(
    principal: PrincipalDep,
    service: QueryServiceDep,
    user_uuid_header: UserUuidDep,
    # Named `preset` in Python, `filter` on the wire: the query parameter has to
    # read as the chip the operator clicked, while shadowing the `filter`
    # builtin inside the function would be a lint failure and a readability one.
    preset: Annotated[
        FilterPreset,
        Query(
            alias="filter",
            description="Filter chip: all, critical, revocation, approval, issuance, verification",
        ),
    ] = FilterPreset.ALL,
    start: Annotated[
        datetime | None,
        Query(description="Earliest event, inclusive. ISO 8601 with an offset."),
    ] = None,
    end: Annotated[datetime | None, Query(description="Latest event, inclusive.")] = None,
    action: Annotated[
        list[str] | None,
        Query(max_length=50, description="Restrict to these actions, e.g. action=credential.issue"),
    ] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    outcome: Annotated[list[Outcome] | None, Query()] = None,
    actor_id: Annotated[list[str] | None, Query(max_length=50)] = None,
    target_id: Annotated[list[str] | None, Query(max_length=50)] = None,
    issuer_id: Annotated[str | None, Query(max_length=64)] = None,
    size: Annotated[int, Query(ge=1, le=200, description="Rows per page.")] = (
        DEFAULT_LISTING_PAGE_SIZE
    ),
    cursor: Annotated[
        str | None,
        Query(max_length=MAX_CURSOR_LENGTH, description="Opaque cursor from the previous page."),
    ] = None,
    with_total: Annotated[
        bool,
        Query(description="Count matches for the 'N events' heading. Capped for cost."),
    ] = True,
) -> ORJSONResponse:
    """One page of the audit log table, ready to render.

    The console's list view and its detail drawer are served by this one call.
    Each row carries both what the table shows - time, event title, category,
    severity badge, target, actor, abbreviated anchor - and what the drawer adds
    when a row is opened: source IP, session, the full event hash and the
    previous one. Opening a row therefore needs no second request.

    Why a GET, when `POST /events/search` exists
    --------------------------------------------
    `search` is a POST because its filter is a structured document, and because
    audit search criteria (actor ids, session ids) are personal data that should
    not land in access logs and browser history. This listing's filters are
    presets, dates and severities - none of them personal - so it can be what a
    console page wants to be: a bookmarkable, shareable, cacheable URL. Pass an
    `actor_id` or `target_id` and you have opted into putting that id in a URL;
    the structured search remains there for filters that should not be.

    `search` is not deprecated by this and is still the right call for a SIEM
    forwarder or a compliance extract, which want canonical ECS documents rather
    than a rendering of them.

    Filtering
    ---------
    `filter` is the chip above the table and narrows by activity - `issuance`
    selects the actions the Category column labels *Issuance*, so the chip and
    the column can never disagree. `critical` selects the severity that draws
    the red badge. Supplying `action` or `severity` as well narrows further
    still: chip AND filter, exactly as the screen reads. A combination that
    excludes everything returns an empty page rather than quietly dropping one
    of the two clauses.

    Integrity
    ---------
    Every row carries `anchor.self_check`, recomputed locally: `pass` means the
    record still hashes to the value stored on it, so it has not been edited in
    place. It is not a full chain verification - proving nothing was deleted,
    reordered or inserted means walking the sequence, which is what the drawer's
    "Verify chain" button calls
    (`POST /v1/audit/compliance/integrity/verify`). `unavailable` means the
    check could not run, typically an event written before chaining was enabled;
    it is not a failure and must not be displayed as one.

    Personal data
    -------------
    Actor names, target names, source IPs and messages are encrypted at rest and
    are returned only to a caller holding `audit:export` or `audit:admin`.
    Without one, those fields come back null and `pii_protected` is true on the
    row, so the console can offer to escalate rather than let a reader take the
    blanks to mean there was nothing there. The row title falls back to a label
    derived from the action, so the table stays readable either way.

    Like every read here, listing the trail is itself recorded as an audit event
    (HIPAA 164.312(b), SOC 2 CC7.2).
    """
    result = await service.list_events(
        principal=principal,
        requested_user_uuid=user_uuid_header,
        preset=preset,
        start=start,
        end=end,
        actions=tuple(action or ()),
        severities=tuple(severity or ()),
        outcomes=tuple(outcome or ()),
        actor_ids=tuple(actor_id or ()),
        target_ids=tuple(target_id or ()),
        issuer_id=issuer_id,
        size=size,
        cursor=decode_cursor(cursor),
        with_total=with_total,
    )
    total = result.total
    if total is None:
        heading = f"{len(result.events)} event(s) returned."
    else:
        heading = f"{total}{'+' if result.total_capped else ''} event(s)."
    return success(result.model_dump(mode="json"), message=heading)


@router.post(
    "/events/search",
    summary="Search audit events",
)
async def search_events(
    payload: Annotated[SearchRequest, Body()],
    principal: PrincipalDep,
    service: QueryServiceDep,
    user_uuid_header: UserUuidHeaderDep,
    cross_user: Annotated[
        bool,
        Query(description="Query across all users. Requires audit:cross_user."),
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
        requested_user_uuid=user_uuid_header,
        cross_user=cross_user,
    )
    return success(result.model_dump(), message=f"{len(result.events)} event(s) returned.")


@router.get(
    "/events/timeline/{target_id}",
    summary="The full history of one entity, oldest first",
)
async def entity_timeline(
    target_id: Annotated[str, Path(max_length=64)],
    principal: PrincipalDep,
    service: QueryServiceDep,
    user_uuid_header: UserUuidDep,
    size: Annotated[int, Query(ge=1, le=500)] = 200,
    action: Annotated[
        list[str] | None,
        Query(description="Restrict to these actions, e.g. action=credential.issue"),
    ] = None,
) -> ORJSONResponse:
    """Everything that happened to one entity, in the order it happened.

    Answers "show me this credential's trail": the issuance steps, the signing
    and anchoring, and every later view, share, reissue or revocation. Pass the
    credential's id (or a record's, or a subject's - the mechanism is the same
    for any entity an event targets).

    A GET with the id in the path rather than a POST body, because unlike a
    search filter an entity id is the resource being addressed. It is not
    personal data, so it is safe in an access log in a way a search over actor
    emails would not be.

    Spans the entire retained history rather than the default search window: a
    credential issued eight months ago is still the answer to a question asked
    today. Bulk-issued credentials are included - those record their id in
    `target.ids` rather than `target.id`, and both are matched.

    User-scoped like every other read. A credential id belonging to another
    user returns an empty timeline, not its history.
    """
    result = await service.timeline(
        target_id,
        principal=principal,
        requested_user_uuid=user_uuid_header,
        size=size,
        actions=tuple(action or ()),
    )
    return success(
        result.model_dump(),
        message=f"{len(result.events)} event(s) in the timeline for {target_id}.",
    )


@router.get(
    "/events/{event_id}",
    summary="Fetch one audit event",
)
async def get_event(
    event_id: Annotated[str, Path(max_length=64)],
    principal: PrincipalDep,
    service: QueryServiceDep,
    user_uuid_header: UserUuidDep,
) -> ORJSONResponse:
    """Fetch a single event by id.

    Still user-filtered: this is a filtered search, not a document GET, so
    guessing an event id from another user returns 404 rather than the record.
    """
    document = await service.get_event(
        event_id, principal=principal, requested_user_uuid=user_uuid_header
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
    user_uuid_header: UserUuidHeaderDep,
    cross_user: Annotated[bool, Query()] = False,
) -> ORJSONResponse:
    """Bucket events by a field, optionally over time.

    `group_by` is restricted to a closed allow-list; an arbitrary field name
    would let a caller aggregate on a high-cardinality keyword and exhaust
    cluster heap.
    """
    aggregations = await service.aggregate(
        payload,
        principal=principal,
        requested_user_uuid=user_uuid_header,
        cross_user=cross_user,
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
    user_uuid_header: UserUuidDep,
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
            payload, principal=principal, requested_user_uuid=user_uuid_header
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
