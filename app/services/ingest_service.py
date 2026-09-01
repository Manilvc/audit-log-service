"""Ingest: validate, resolve the tenant, enqueue.

Deliberately thin and fast. Everything expensive - encryption, hash chaining,
Elasticsearch, the WORM archive - happens in the worker, so an emitting service
never waits on it. An audit write that adds latency to credential issuance is an
audit write that someone will eventually be tempted to make optional.

Tenant resolution is the security-critical part. The tenant is taken from the
authenticated principal, and a body-supplied `tenant_id` is only honoured when it
matches. Without that reconciliation, any service key could write events into
any tenant's trail - forged evidence, which is worse than missing evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.config import Settings
from app.core.exceptions import IngestRejected
from app.core.logging import get_logger
from app.core.metrics import EVENTS_INGESTED
from app.core.security.auth import Principal
from app.domain.enums import Scope
from app.queue.stream import IngestQueue
from app.schemas.api import AuditEventIn, IngestAccepted
from app.search.routing import InvalidTenantError, TenantRouter

logger = get_logger(__name__)


@dataclass(slots=True)
class _Rejection:
    index: int
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"index": self.index, "reason": self.reason}


class IngestService:
    """Accepts audit events onto the durable queue."""

    def __init__(
        self,
        *,
        settings: Settings,
        queue: IngestQueue,
        router: TenantRouter,
    ) -> None:
        self._settings = settings
        self._queue = queue
        self._router = router

    async def ingest(
        self,
        events: list[AuditEventIn],
        *,
        principal: Principal,
        header_tenant_id: str | None,
    ) -> IngestAccepted:
        """Validate and enqueue a batch.

        Partial success is intentional: one malformed event in a batch of 500
        must not discard the other 499. Rejections are reported per index so the
        emitter can fix and resend only the bad ones.

        Raises:
            IngestRejected: the caller lacks the write scope, the batch is over
                the size limit, or no tenant can be resolved for the whole batch.
        """
        principal.require(Scope.WRITE)

        if len(events) > self._settings.MAX_INGEST_BATCH_SIZE:
            raise IngestRejected(
                f"batch of {len(events)} exceeds the maximum of "
                f"{self._settings.MAX_INGEST_BATCH_SIZE} events"
            )

        queued: list[tuple[int, dict[str, Any]]] = []
        event_ids: list[str] = []
        rejections: list[_Rejection] = []

        for index, incoming in enumerate(events):
            try:
                tenant_id = self._resolve_tenant(
                    principal=principal,
                    header_tenant_id=header_tenant_id,
                    body_tenant_id=incoming.tenant_id,
                )
            except (IngestRejected, InvalidTenantError) as exc:
                rejections.append(_Rejection(index=index, reason=str(exc)))
                continue

            try:
                event = incoming.to_domain(
                    tenant_id=tenant_id,
                    max_clock_skew_seconds=self._settings.MAX_CLOCK_SKEW_SECONDS,
                )
                if event.labels.get("clock_skew_suspect"):
                    # Warn once per event rather than per batch: the operator
                    # needs to know *which* emitter's clock is wrong, and
                    # service_name is the only handle on that.
                    logger.warning(
                        "event_clock_skew",
                        tenant_id=tenant_id,
                        service_name=event.service_name,
                        action=event.action,
                        skew_seconds=event.labels.get("clock_skew_seconds"),
                        tolerance_seconds=self._settings.MAX_CLOCK_SKEW_SECONDS,
                    )
            except Exception as exc:
                rejections.append(_Rejection(index=index, reason=f"invalid event: {exc}"))
                continue

            partition = self._router.partition_for(tenant_id, self._settings.STREAM_PARTITIONS)
            # The queue carries the *domain* shape, so the worker re-validates
            # against the same model rather than trusting a wire payload that
            # may have been queued by an older build.
            queued.append((partition, event.model_dump(mode="json")))
            event_ids.append(event.event_id)

        if queued:
            await self._queue.publish_many(queued)

        if queued:
            EVENTS_INGESTED.labels(outcome="accepted").inc(len(queued))
        if rejections:
            EVENTS_INGESTED.labels(outcome="rejected").inc(len(rejections))
            logger.warning(
                "ingest_partial_rejection",
                accepted=len(queued),
                rejected=len(rejections),
                first_reason=rejections[0].reason,
                principal=principal.audit_identity,
            )

        return IngestAccepted(
            accepted=len(queued),
            rejected=len(rejections),
            event_ids=event_ids,
            errors=[rejection.as_dict() for rejection in rejections],
        )

    def _resolve_tenant(
        self,
        *,
        principal: Principal,
        header_tenant_id: str | None,
        body_tenant_id: str | None,
    ) -> str:
        """Determine which tenant an event belongs to.

        Precedence:
          1. A user principal's own `tenant_id` claim wins outright. A user
             token cannot write into another tenant, full stop.
          2. A service principal uses the `x-audit-tenant-id` header, since it
             legitimately acts for many tenants.
          3. A body-supplied `tenant_id` is accepted only when it agrees with
             the resolved value, so it can never widen access - only confirm it.

        Raises:
            IngestRejected: no tenant could be resolved, or the body contradicts
                the authenticated tenant.
        """
        authoritative = principal.tenant_id or (header_tenant_id if principal.is_service else None)

        if authoritative is None and principal.is_service:
            authoritative = body_tenant_id

        if not authoritative:
            raise IngestRejected(
                "cannot determine the tenant for this event: the token carries no "
                "tenant_id and no x-audit-tenant-id header was supplied"
            )

        if body_tenant_id and body_tenant_id != authoritative:
            # A mismatch is treated as an attempted cross-tenant write and is
            # logged at error level, because a correct emitter never does this.
            logger.error(
                "tenant_mismatch_rejected",
                authenticated_tenant=authoritative,
                body_tenant=body_tenant_id,
                principal=principal.audit_identity,
            )
            raise IngestRejected(
                "tenant_id in the event body does not match the authenticated tenant"
            )

        return self._router.validate_tenant_id(authoritative)
