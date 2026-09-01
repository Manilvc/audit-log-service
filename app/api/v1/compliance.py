"""Compliance endpoints: integrity verification and data-subject erasure.

Mounted under ``/v1/audit/compliance``. Both operations require a *single*
named tenant — cross-tenant scope is refused, because verifying or shredding
"every tenant at once" is not a meaningful compliance action.

``POST .../integrity/verify`` (``audit:verify``)
    Walks each hash chain for the tenant and reports breaks
    (``hash_mismatch``, ``gap``, ``duplicate_seq``, ``prev_mismatch``).
``POST .../erasure`` (``audit:erase``)
    Crypto-shreds a data subject's DEK. Structural evidence stays; PII becomes
    permanently unreadable. Deliberately unavailable to service API keys.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body

from app.api.deps import (
    ErasureServiceDep,
    IntegrityServiceDep,
    PrincipalDep,
    QueryServiceDep,
    TenantHeaderDep,
)
from app.core.logging import get_logger
from app.core.responses import ORJSONResponse, success
from app.core.security.auth import AuthorizationError
from app.schemas.api import ErasureRequest, IntegrityVerifyRequest
from app.search.query import TenantScope

logger = get_logger(__name__)

router = APIRouter(prefix="/audit/compliance", tags=["Compliance"])


def _require_tenant(scope: TenantScope) -> str:
    """Narrow a scope to a concrete tenant id.

    A real check rather than an ``assert``: asserts are stripped under
    ``python -O``, and both callers here perform an irreversible or
    evidence-bearing operation that must never run without a tenant.
    Cross-tenant scopes are refused outright - verifying or erasing across
    every tenant at once is not a meaningful operation.
    """
    if scope.cross_tenant or not scope.tenant_id:
        raise AuthorizationError(
            "this operation requires a single named tenant; cross-tenant scope is not accepted here"
        )
    return scope.tenant_id


@router.post(
    "/integrity/verify",
    summary="Verify the tamper-evidence hash chain",
)
async def verify_integrity(
    payload: Annotated[IntegrityVerifyRequest, Body()],
    principal: PrincipalDep,
    integrity: IntegrityServiceDep,
    query: QueryServiceDep,
    tenant_header: TenantHeaderDep,
) -> ORJSONResponse:
    """Recompute the hash chain and report any discontinuity.

    Detects three distinct attacks, and says which one it found:

    * **hash_mismatch** - a stored record was modified in place.
    * **gap** / **duplicate_seq** - records were deleted or replayed.
    * **prev_mismatch** - records were reordered or inserted.

    The report also carries the most recent WORM-notarised checkpoint. That
    matters: a chain verifying against itself only proves internal consistency,
    while the immutable checkpoint is what makes a wholesale rewrite detectable.

    Requires the `audit:verify` scope. `intact: false` in the response is a
    security incident, not a validation error, so the call still returns 200 -
    the verification itself succeeded.
    """
    tenant_id = _require_tenant(query.resolve_scope(principal, requested_tenant_id=tenant_header))
    report = await integrity.verify(payload, principal=principal, tenant_id=tenant_id)
    return success(
        report.model_dump(mode="json"),
        message=(
            "Hash chain verified; no tampering detected."
            if report.intact
            else f"INTEGRITY FAILURE: {len(report.breaks)} discontinuity(ies) detected."
        ),
    )


@router.post(
    "/erasure",
    summary="Erase a data subject's personal data (GDPR Art. 17 / DPDP s.12)",
)
async def erase_subject(
    payload: Annotated[ErasureRequest, Body()],
    principal: PrincipalDep,
    erasure: ErasureServiceDep,
    query: QueryServiceDep,
    tenant_header: TenantHeaderDep,
) -> ORJSONResponse:
    """Crypto-shred one data subject's personal data.

    **Irreversible.** The subject's encryption key is destroyed, so the personal
    data inside their audit records becomes permanently unreadable - by anyone,
    including the platform operator.

    No audit record is modified or deleted. The events stay in place with their
    hash chain intact, which is how the right to erasure is honoured on a log
    that SOC 2, ISO 27001 and HIPAA require to be immutable. Structural fields -
    who acted, on what, when, with what outcome - survive as evidence; only the
    personal data becomes unreadable.

    Requires the `audit:erase` scope and explicit `confirm: true`. The erasure is
    itself audited at CRITICAL severity.
    """
    tenant_id = _require_tenant(query.resolve_scope(principal, requested_tenant_id=tenant_header))
    receipt = await erasure.erase(payload, principal=principal, tenant_id=tenant_id)
    return success(
        receipt.model_dump(mode="json"),
        message=(
            f"Erasure complete. {receipt.affected_events} audit record(s) had "
            "personal data rendered permanently unreadable; the records "
            "themselves are retained as required audit evidence."
        ),
    )
