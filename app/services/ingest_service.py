"""Ingest: validate, resolve the user, enqueue.

Deliberately thin and fast. Everything expensive - encryption, hash chaining,
Elasticsearch, the WORM archive - happens in the worker, so an emitting service
never waits on it. An audit write that adds latency to credential issuance is an
audit write that someone will eventually be tempted to make optional.

User resolution is the security-critical part. The user is taken from the
authenticated principal, and a body-supplied `user_uuid` is only honoured when it
matches. Without that reconciliation, any service key could write events into
any user's trail - forged evidence, which is worse than missing evidence.
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
from app.search.routing import InvalidUserUuidError, UserRouter

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
        router: UserRouter,
    ) -> None:
        self._settings = settings
        self._queue = queue
        self._router = router

    async def ingest(
        self,
        events: list[AuditEventIn],
        *,
        principal: Principal,
        header_user_uuid: str | None,
        header_issuer_id: str | None = None,
    ) -> IngestAccepted:
        """Validate and enqueue a batch.

        Partial success is intentional: one malformed event in a batch of 500
        must not discard the other 499. Rejections are reported per index so the
        emitter can fix and resend only the bad ones.

        Raises:
            IngestRejected: the caller lacks the write scope, the batch is over
                the size limit, or no user can be resolved for the whole batch.
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
                user_uuid = self._resolve_user(
                    principal=principal,
                    header_user_uuid=header_user_uuid,
                    body_user_uuid=incoming.user_uuid,
                )
            except (IngestRejected, InvalidUserUuidError) as exc:
                rejections.append(_Rejection(index=index, reason=str(exc)))
                continue

            try:
                event = incoming.to_domain(
                    user_uuid=user_uuid,
                    issuer_id=header_issuer_id,
                    # Who actually submitted this, taken from the request rather
                    # than from the event body. An emitter that forgets to fill
                    # in its own name or the user it is acting for still produces
                    # an attributable record.
                    submitted_by=principal.subject,
                    on_behalf_of=principal.on_behalf_of,
                    max_clock_skew_seconds=self._settings.MAX_CLOCK_SKEW_SECONDS,
                )
                if event.labels.get("clock_skew_suspect"):
                    # Warn once per event rather than per batch: the operator
                    # needs to know *which* emitter's clock is wrong, and
                    # service_name is the only handle on that.
                    logger.warning(
                        "event_clock_skew",
                        user_uuid=user_uuid,
                        service_name=event.service_name,
                        action=event.action,
                        skew_seconds=event.labels.get("clock_skew_seconds"),
                        tolerance_seconds=self._settings.MAX_CLOCK_SKEW_SECONDS,
                    )
            except Exception as exc:
                rejections.append(_Rejection(index=index, reason=f"invalid event: {exc}"))
                continue

            partition = self._router.partition_for(user_uuid, self._settings.STREAM_PARTITIONS)
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

    def _resolve_user(
        self,
        *,
        principal: Principal,
        header_user_uuid: str | None,
        body_user_uuid: str | None,
    ) -> str:
        """Determine which user an event belongs to.

        Precedence:
          1. The `x-audit-user-uuid` header, which is how a service names the
             user it is acting for. A service legitimately writes for many
             users, so the user is per-request rather than bound to the key.
          2. A body-supplied `user_uuid`, used only when no header was sent, so
             a batch can be self-describing. Unreachable over HTTP - the ingest
             route takes `UserUuidDep` and refuses a call with no header - and
             kept for callers that are not the route: the CLI, a backfill, a
             replay.
          3. When both are present they must agree: a body value can never
             redirect the write, only confirm it. This is the rule that stays
             live in production, and the one worth reading first.

        Raises:
            IngestRejected: no user could be resolved, or the body contradicts
                the header.
        """
        authoritative = header_user_uuid or principal.user_uuid or body_user_uuid

        if not authoritative:
            raise IngestRejected(
                "cannot determine the user for this event: no x-audit-user-uuid "
                "header was supplied and the event body carries no user_uuid"
            )

        if body_user_uuid and body_user_uuid != authoritative:
            # A mismatch is treated as an attempted cross-user write and is
            # logged at error level, because a correct emitter never does this.
            logger.error(
                "user_uuid_mismatch_rejected",
                header_user=authoritative,
                body_user=body_user_uuid,
                principal=principal.audit_identity,
            )
            raise IngestRejected(
                "user_uuid in the event body does not match the x-audit-user-uuid header"
            )

        return self._router.validate_user_uuid(authoritative)
