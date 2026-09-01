"""Compliance operations: integrity verification and data-subject erasure.

The two sit together because they are the pair that makes an immutable audit log
lawful. Verification proves nothing was altered; erasure honours a data
principal's rights *without* altering anything. Reading them side by side is the
clearest way to see that the guarantees do not conflict.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.core.integrity import GENESIS_HASH, verify_chain
from app.core.logging import get_logger
from app.core.security.auth import Principal
from app.core.security.crypto import PiiCipher
from app.domain.enums import Action, EventCategory, EventType, Outcome, Scope, Severity
from app.queue.stream import IngestQueue
from app.schemas.api import (
    ErasureReceipt,
    ErasureRequest,
    IntegrityReport,
    IntegrityVerifyRequest,
)
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter

logger = get_logger(__name__)


class IntegrityService:
    """Verifies hash chains against the ledger and the notarised checkpoints."""

    def __init__(
        self,
        *,
        settings: Settings,
        repository: AuditRepository,
        router: TenantRouter,
        archive: Any,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._router = router
        self._archive = archive

    async def verify(
        self,
        request: IntegrityVerifyRequest,
        *,
        principal: Principal,
        tenant_id: str,
    ) -> IntegrityReport:
        """Verify one chain, or every chain for a tenant.

        A chain slice is only meaningful evidence when the verifier knows where
        it should start. Verifying from `start_seq=0` asserts contiguity from the
        beginning, so a deleted prefix is detected. Starting mid-chain cannot
        make that assertion - sequences before the window are simply unknown -
        so contiguity is only enforced when the caller starts at zero.
        """
        principal.require(Scope.VERIFY)

        chain_ids = (
            [request.chain_id]
            if request.chain_id
            else [
                self._router.chain_id(tenant_id, partition)
                for partition in range(self._settings.STREAM_PARTITIONS)
            ]
        )

        all_breaks: list[dict[str, Any]] = []
        verified_total = 0
        chains_with_data = 0

        for chain_id in chain_ids:
            documents = await self._repository.fetch_chain_slice(
                chain_id=chain_id,
                tenant_id=tenant_id,
                start_seq=request.start_seq,
                limit=request.max_events,
            )
            if not documents:
                continue
            chains_with_data += 1

            result = verify_chain(
                chain_id,
                documents,
                expected_start_hash=(
                    GENESIS_HASH if request.start_seq == 0 else _prev_hash_of(documents[0])
                ),
                expect_contiguous_from=(0 if request.start_seq == 0 else None),
            )
            verified_total += result.verified_count
            all_breaks.extend(
                {
                    "chain_id": chain_id,
                    "seq": break_.seq,
                    "event_id": break_.event_id,
                    "kind": break_.kind,
                    "detail": break_.detail,
                }
                for break_ in result.breaks
            )

        checkpoint = await self._latest_checkpoint(tenant_id, chain_ids)

        report = IntegrityReport(
            tenant_id=tenant_id,
            chains_checked=chains_with_data,
            events_verified=verified_total,
            intact=not all_breaks,
            breaks=all_breaks,
            checkpoint=checkpoint,
            verified_at=datetime.now(UTC),
        )

        if all_breaks:
            # This is the alarm that matters: a broken chain means records were
            # altered or removed. Logged at error level with the detail an
            # incident responder needs immediately.
            logger.error(
                "integrity_verification_failed",
                tenant_id=tenant_id,
                break_count=len(all_breaks),
                kinds=sorted({break_["kind"] for break_ in all_breaks}),
            )
        else:
            logger.info(
                "integrity_verified",
                tenant_id=tenant_id,
                chains=chains_with_data,
                events=verified_total,
            )
        return report

    async def _latest_checkpoint(
        self, tenant_id: str, chain_ids: list[str]
    ) -> dict[str, Any] | None:
        """Most recent WORM-notarised checkpoint across the chains checked.

        Included in every report because a chain that verifies against itself
        only proves internal consistency. The immutable checkpoint is what turns
        that into proof against a wholesale rewrite.
        """
        if self._archive is None or not getattr(self._archive, "enabled", False):
            return None
        newest: dict[str, Any] | None = None
        for chain_id in chain_ids:
            try:
                candidate = await self._archive.latest_checkpoint(
                    tenant_id=tenant_id, chain_id=chain_id
                )
            except Exception as exc:
                logger.warning("checkpoint_lookup_failed", chain_id=chain_id, error=str(exc))
                continue
            if candidate and (
                newest is None or int(candidate.get("seq", -1)) > int(newest.get("seq", -1))
            ):
                newest = candidate
        return newest


class ErasureService:
    """Executes data-subject erasure by destroying key material."""

    def __init__(
        self,
        *,
        settings: Settings,
        repository: AuditRepository,
        router: TenantRouter,
        cipher: PiiCipher,
        keyring: Any,
        queue: IngestQueue,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._router = router
        self._cipher = cipher
        self._keyring = keyring
        self._queue = queue

    async def erase(
        self,
        request: ErasureRequest,
        *,
        principal: Principal,
        tenant_id: str,
    ) -> ErasureReceipt:
        """Destroy the key protecting one data subject's PII.

        No audit document is modified or deleted. The records stay in place with
        their hash chain intact, and the personal data inside them becomes
        permanently unreadable. That is what lets GDPR Art. 17 and DPDP s.12 be
        honoured on an append-only log that SOC 2, ISO 27001 and HIPAA require to
        be immutable.

        The operation is irreversible: after this returns, nobody - including the
        platform operator - can recover the plaintext.

        Raises:
            AuthorizationError: the caller lacks `audit:erase`.
        """
        principal.require(Scope.ERASE)

        key_id = self._cipher.subject_key_id(tenant_id, request.subject_id)

        # Count first: once the key is gone the documents are still countable by
        # key_id, but reporting the figure is a GDPR Art. 19 obligation and
        # doing it beforehand keeps the receipt accurate even if the count query
        # later fails.
        affected = await self._repository.count_by_key_id(tenant_id=tenant_id, key_id=key_id)

        destroyed = await self._keyring.delete(
            key_id,
            reason=request.reason,
            request_id=request.request_reference,
        )

        # The erasure is itself an audit event - and one of the most important
        # in the system, since it is the only operation that renders evidence
        # unreadable. Note it records the key id and subject id, never the
        # personal data being erased.
        audit_event_id = await self._record_erasure(
            principal=principal,
            tenant_id=tenant_id,
            subject_id=request.subject_id,
            key_id=key_id,
            affected=affected,
            request=request,
            destroyed=destroyed,
        )

        logger.warning(
            "data_subject_erasure_executed",
            tenant_id=tenant_id,
            key_id=key_id,
            affected_events=affected,
            destroyed=destroyed,
            requested_by=principal.audit_identity,
            reference=request.request_reference,
        )

        return ErasureReceipt(
            subject_id=request.subject_id,
            key_id=key_id,
            destroyed=destroyed,
            affected_events=affected,
            erased_at=datetime.now(UTC),
            audit_event_id=audit_event_id,
        )

    async def _record_erasure(
        self,
        *,
        principal: Principal,
        tenant_id: str,
        subject_id: str,
        key_id: str,
        affected: int,
        request: ErasureRequest,
        destroyed: bool,
    ) -> str:
        """Queue the audit event for this erasure.

        Unlike the read-audit path, a failure here is *not* swallowed: an
        unrecorded erasure is an undocumented destruction of evidence, which is
        precisely what an auditor would treat as a finding.
        """
        import uuid

        event_id = str(uuid.uuid4())
        partition = self._router.partition_for(tenant_id, self._settings.STREAM_PARTITIONS)
        await self._queue.publish(
            partition,
            {
                "event_id": event_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "tenant_id": tenant_id,
                "action": Action.AUDIT_ERASURE_REQUEST.value,
                "category": EventCategory.AUDIT.value,
                "type": EventType.DELETION.value,
                "outcome": Outcome.SUCCESS.value,
                "severity": Severity.CRITICAL.value,
                "reason": request.reason[:1024],
                "actor": {
                    "type": principal.actor_type.value,
                    "id": principal.subject,
                    "session_id": principal.session_id,
                    "on_behalf_of": principal.on_behalf_of,
                },
                "target": {
                    "type": "audit_log",
                    # The subject id is an identifier, not personal data, and it
                    # must survive: without it there is no proof which DSR was
                    # honoured.
                    "id": subject_id,
                    "count": affected,
                },
                "service_name": self._settings.SERVICE_NAME,
                "labels": {
                    "key_id": key_id,
                    "affected_events": affected,
                    "newly_destroyed": destroyed,
                    "request_reference": request.request_reference,
                    "legal_basis": "gdpr_art_17/dpdp_s_12",
                },
            },
        )
        return event_id


def _prev_hash_of(document: dict[str, Any]) -> str:
    """The `prev_hash` a mid-chain slice declares for its first document.

    Used as the expected start hash when verifying a window: it makes the check
    self-consistent within the slice, while contiguity from the chain's origin
    is deliberately not asserted.
    """
    integrity = document.get("integrity") or {}
    return str(integrity.get("prev_hash", GENESIS_HASH))
