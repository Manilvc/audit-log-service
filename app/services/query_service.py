"""Read path: scope resolution, decryption, and the audit-of-the-audit trail.

Three responsibilities, all of them security-relevant:

1. **Turn a principal into a `TenantScope`.** This is where "who may see what"
   is decided. A user token with no explicit grant is pinned to its own events;
   cross-tenant access requires a dedicated scope.
2. **Decrypt PII for display**, and only for a caller that is allowed to see it.
3. **Audit every read.** HIPAA 164.312(b) and SOC 2 CC7.2 both require that
   access to the audit trail is itself logged. A reader who can search without
   leaving a trace defeats the purpose of the log.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.core.logging import get_logger
from app.core.security.auth import AuthorizationError, Principal
from app.core.security.crypto import PiiCipher
from app.domain.enums import Action, EventCategory, EventType, Outcome, Scope, Severity
from app.queue.stream import IngestQueue
from app.schemas.api import (
    AggregationRequest,
    ExportRequest,
    SearchRequest,
    SearchResponse,
)
from app.search.query import AuditSearchFilter, TenantScope
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter

logger = get_logger(__name__)

#: Field paths a caller may restrict `_source` to. An allow-list rather than a
#: pass-through so `pii_ct` can never be requested directly.
_ALLOWED_SOURCE_FIELDS = frozenset(
    {
        "@timestamp",
        "event",
        "event.id",
        "event.action",
        "event.category",
        "event.type",
        "event.outcome",
        "event.severity",
        "event.reason",
        "tenant",
        "tenant.id",
        "tenant.issuer_id",
        "actor",
        "actor.id",
        "actor.type",
        "actor.session_id",
        "target",
        "target.id",
        "target.type",
        "source",
        "source.country_code",
        "source.ip_prefix",
        "http",
        "change",
        "labels",
        "service",
        "message",
        "integrity",
    }
)


class QueryService:
    """Serves audit reads."""

    def __init__(
        self,
        *,
        settings: Settings,
        repository: AuditRepository,
        router: TenantRouter,
        cipher: PiiCipher,
        queue: IngestQueue,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._router = router
        self._cipher = cipher
        self._queue = queue

    # ------------------------------------------------------------------ scope
    def resolve_scope(
        self,
        principal: Principal,
        *,
        requested_tenant_id: str | None = None,
        cross_tenant: bool = False,
    ) -> TenantScope:
        """Derive the authorised query boundary for a principal.

        Raises:
            AuthorizationError: cross-tenant access was requested without the
                scope, a service named no tenant, or a tenant-scoped caller
                asked for a tenant other than its own.
        """
        if cross_tenant:
            if not principal.has(Scope.CROSS_TENANT):
                raise AuthorizationError(
                    "cross-tenant audit access requires the audit:cross_tenant scope"
                )
            return TenantScope(tenant_id=None, cross_tenant=True)

        if principal.is_service:
            tenant_id = requested_tenant_id or principal.tenant_id
            if not tenant_id:
                raise AuthorizationError(
                    "a service must name the tenant it is querying via x-audit-tenant-id"
                )
        else:
            tenant_id = principal.tenant_id
            if not tenant_id:
                raise AuthorizationError("token carries no tenant_id claim")
            # A user token may never be redirected at another tenant, even by an
            # admin: crossing a tenant boundary is what audit:cross_tenant is for.
            if requested_tenant_id and requested_tenant_id != tenant_id:
                raise AuthorizationError(
                    "cannot query another tenant; use the audit:cross_tenant scope"
                )

        return TenantScope(
            tenant_id=self._router.validate_tenant_id(tenant_id),
            cross_tenant=False,
            # An unscoped user token sees only its own events. This is the
            # narrow default that makes a plain platform token safe to accept.
            actor_id=principal.subject if principal.restricted_to_self else None,
        )

    # ----------------------------------------------------------------- search
    async def search(
        self,
        request: SearchRequest,
        *,
        principal: Principal,
        requested_tenant_id: str | None = None,
        cross_tenant: bool = False,
    ) -> SearchResponse:
        """Run a paginated search and record that it happened."""
        principal.require(Scope.READ)
        scope = self.resolve_scope(
            principal,
            requested_tenant_id=requested_tenant_id,
            cross_tenant=cross_tenant,
        )

        page = await self._repository.search(
            scope,
            _to_filter(request),
            size=min(request.size, self._settings.MAX_PAGE_SIZE),
            search_after=request.cursor,
            with_total=(self._settings.TOTAL_HITS_CAP if request.with_total else False),
            source_fields=_validated_fields(request.fields),
        )

        events = await self._reveal(page.events, principal=principal)

        await self.record_access(
            principal=principal,
            scope=scope,
            action=(Action.AUDIT_CROSS_TENANT_ACCESS if cross_tenant else Action.AUDIT_SEARCH),
            result_count=len(events),
            detail={
                "size": request.size,
                "paginated": request.cursor is not None,
                "actions_filter": request.actions[:10],
            },
        )

        return SearchResponse(
            events=events,
            # Only hand back a cursor when the page was full; otherwise the
            # caller would make one extra empty request per result set.
            cursor=page.next_cursor if len(page.events) == request.size else None,
            total=page.total,
            took_ms=page.took_ms,
            partial=page.timed_out,
        )

    async def get_event(
        self,
        event_id: str,
        *,
        principal: Principal,
        requested_tenant_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch a single event, tenant-filtered."""
        principal.require(Scope.READ)
        scope = self.resolve_scope(principal, requested_tenant_id=requested_tenant_id)
        document = await self._repository.get_event(scope, event_id)
        if document is None:
            return None
        revealed = await self._reveal([document], principal=principal)
        return revealed[0]

    async def aggregate(
        self,
        request: AggregationRequest,
        *,
        principal: Principal,
        requested_tenant_id: str | None = None,
        cross_tenant: bool = False,
    ) -> dict[str, Any]:
        """Run a dashboard aggregation.

        `group_by` is already constrained to an allow-list by the schema, so no
        caller-supplied field name reaches the cluster.
        """
        principal.require(Scope.READ)
        scope = self.resolve_scope(
            principal,
            requested_tenant_id=requested_tenant_id,
            cross_tenant=cross_tenant,
        )
        aggregations = await self._repository.aggregate(
            scope,
            _to_filter(request),
            group_by=request.group_by,
            interval=request.interval,
            size=request.buckets,
        )
        return aggregations

    # ----------------------------------------------------------------- export
    async def export(
        self,
        request: ExportRequest,
        *,
        principal: Principal,
        requested_tenant_id: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream every matching event over a point-in-time snapshot.

        A generator rather than a list: a million-event export must never be
        assembled in memory. The PIT freezes the view, so events arriving
        mid-export do not turn the extract into a smear across time - which
        would make it useless as evidence.

        The export is audited *before* the first document is yielded, so an
        aborted download still leaves a record that the extract was requested.
        """
        principal.require(Scope.EXPORT)
        scope = self.resolve_scope(principal, requested_tenant_id=requested_tenant_id)
        criteria = _to_filter(request)

        await self.record_access(
            principal=principal,
            scope=scope,
            action=Action.AUDIT_EXPORT,
            result_count=0,
            detail={"max_events": request.max_events, "streaming": True},
        )

        pit_id = await self._repository.open_pit(scope, keep_alive="5m")
        emitted = 0
        cursor: list[Any] | None = None
        try:
            while emitted < request.max_events:
                page = await self._repository.search_pit(
                    scope,
                    criteria,
                    pit_id=pit_id,
                    size=min(self._settings.MAX_PAGE_SIZE, request.max_events - emitted),
                    search_after=cursor,
                )
                if not page.events:
                    break
                revealed = await self._reveal(page.events, principal=principal)
                for document in revealed:
                    if not request.include_integrity:
                        document.pop("integrity", None)
                    yield document
                    emitted += 1
                if page.next_cursor is None or len(page.events) < 1:
                    break
                cursor = page.next_cursor
        finally:
            # Always released: a leaked PIT pins Lucene segments and blocks
            # disk reclamation.
            await self._repository.close_pit(pit_id)
            logger.info(
                "export_completed",
                events=emitted,
                principal=principal.audit_identity,
                tenant_id=scope.tenant_id,
            )

    # ------------------------------------------------------------- decryption
    async def _reveal(
        self, documents: list[dict[str, Any]], *, principal: Principal
    ) -> list[dict[str, Any]]:
        """Decrypt PII for callers permitted to see it.

        A caller without the export or admin scope gets the event structure with
        PII left as ciphertext markers. Most audit review - who did what, when,
        with what outcome - needs no personal data at all, so revealing it by
        default would be an unnecessary standing exposure.
        """
        if not self._cipher.enabled:
            return documents

        may_decrypt = principal.has(Scope.ADMIN) or principal.has(Scope.EXPORT)
        if not may_decrypt:
            return [_mask_ciphertext(document) for document in documents]

        revealed: list[dict[str, Any]] = []
        for document in documents:
            revealed.append(await self._cipher.decrypt_document(document))
        return revealed

    # ------------------------------------------------ audit-of-the-audit trail
    async def record_access(
        self,
        *,
        principal: Principal,
        scope: TenantScope,
        action: Action,
        result_count: int,
        detail: dict[str, Any],
    ) -> None:
        """Emit an audit event recording this read.

        Failures are swallowed. This mirrors the main backend's
        `AuditLogService`: a problem writing the meta-audit event must not fail
        the caller's query. The queue is durable, so the realistic failure here
        is Redis being unreachable, which is already alerted on.
        """
        try:
            tenant_id = scope.tenant_id or "cross-tenant"
            partition = self._router.partition_for(
                tenant_id if scope.tenant_id else "cross-tenant",
                self._settings.STREAM_PARTITIONS,
            )
            payload = {
                "event_id": None,
                "timestamp": datetime.now(UTC).isoformat(),
                "tenant_id": tenant_id,
                "action": action.value,
                "category": EventCategory.AUDIT.value,
                "type": EventType.ACCESS.value,
                "outcome": Outcome.SUCCESS.value,
                "severity": (
                    Severity.CRITICAL.value
                    if action is Action.AUDIT_CROSS_TENANT_ACCESS
                    else Severity.INFO.value
                ),
                "actor": {
                    "type": principal.actor_type.value,
                    "id": principal.subject,
                    "session_id": principal.session_id,
                    "on_behalf_of": principal.on_behalf_of,
                    "service": principal.subject if principal.is_service else None,
                },
                "target": {"type": "audit_log", "count": result_count},
                "service_name": self._settings.SERVICE_NAME,
                "labels": {
                    "result_count": result_count,
                    "cross_tenant": scope.cross_tenant,
                    "self_restricted": scope.actor_id is not None,
                    **detail,
                },
            }
            # `event_id` is dropped so the worker assigns a fresh one; a None id
            # would otherwise become the ES document id.
            payload.pop("event_id")
            await self._queue.publish(partition, payload)
        except Exception as exc:
            logger.error("audit_of_audit_write_failed", error=str(exc), action=action.value)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _to_filter(request: SearchRequest) -> AuditSearchFilter:
    """Translate the wire request into the internal filter."""
    return AuditSearchFilter(
        start=request.start,
        end=request.end,
        actions=tuple(request.actions),
        categories=tuple(request.categories),
        outcomes=tuple(request.outcomes),
        severities=tuple(request.severities),
        actor_ids=tuple(request.actor_ids),
        actor_types=tuple(actor.value for actor in request.actor_types),
        session_id=request.session_id,
        target_ids=tuple(request.target_ids),
        target_types=tuple(entity.value for entity in request.target_types),
        issuer_id=request.issuer_id,
        service_names=tuple(request.service_names),
        request_id=request.request_id,
        trace_id=request.trace_id,
        event_ids=tuple(request.event_ids),
        ip_prefix=request.ip_prefix,
        country_codes=tuple(request.country_codes),
        http_status_min=request.http_status_min,
        http_status_max=request.http_status_max,
        label_terms=request.label_terms,
        text=request.text,
    )


def _validated_fields(fields: list[str] | None) -> list[str] | None:
    """Filter requested `_source` paths against the allow-list.

    Silently dropping an unknown path is preferred to a 400: the caller still
    gets a usable response, and `pii_ct` can never be smuggled in.
    """
    if not fields:
        return None
    allowed = [field for field in fields if field in _ALLOWED_SOURCE_FIELDS]
    return allowed or None


def _mask_ciphertext(document: dict[str, Any]) -> dict[str, Any]:
    """Replace encrypted blobs with a marker for a caller without decrypt rights.

    The marker matters: it tells the reader that personal data exists on this
    event, so they know to request elevated access rather than assuming the
    field was empty.
    """
    ciphertexts = document.pop("pii_ct", None)
    if isinstance(ciphertexts, dict):
        for path in ciphertexts:
            _set_masked(document, path)
    return document


def _set_masked(document: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    node = document
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = "[PROTECTED]"
