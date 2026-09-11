"""Issuing and revoking the keys emitters authenticate with.

Mounted under ``/v1/audit/admin/api-keys``. Every route needs ``audit:admin``,
which only the env-configured `SERVICE_API_KEYS` carry - an issued key can never
hold it, so a leaked emitter credential cannot mint more of itself.

The user comes from ``x-audit-user-uuid``, not from the body. A key is bound
to the user named on the request that created it, which means an admin cannot
mint a key for a user they did not name in the header the gateway can see.

A key minted with ``all_users: true`` is **unbound**: it carries no user, and
the same header names the user on each later request. That is the shape a
single backend serving every user needs. It stays weaker than the env
credential - the forbidden scopes are still refused - and unlike an env key it
has a record, so it can be listed, attributed and revoked.

Routes
------
``POST /api-keys``
    Mint a key for one user and one emitting domain. **The plaintext is in the
    response and nowhere else** - it is never stored and never logged.
``GET /api-keys``
    List the user's keys. Never includes a secret.
``DELETE /api-keys/{key_id}``
    Revoke. The record stays: "revoked on the 3rd" is evidence, "no such key"
    is not.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, status

from app.api.deps import ApiKeyServiceDep, PrincipalDep, UserUuidDep, UserUuidHeaderDep
from app.core.constants import API_KEY_LIST_MAX_SIZE
from app.core.exceptions import IngestRejected, NotFound
from app.core.logging import get_logger
from app.core.responses import ORJSONResponse, success
from app.domain.enums import Scope
from app.schemas.api import ApiKeyIssued, ApiKeyIssueRequest, ApiKeyListResponse, ApiKeySummary
from app.search.api_key_store import ApiKeyRecord
from app.services.api_key_service import ApiKeyError, build_key_hint

logger = get_logger(__name__)

router = APIRouter(prefix="/audit/admin/api-keys", tags=["API Keys"])


def _to_summary(record: ApiKeyRecord) -> ApiKeySummary:
    """Render a stored key for a management view. Carries no secret material."""
    return ApiKeySummary(
        key_id=record.key_id,
        user_uuid=record.user_uuid,
        domain=record.domain,
        label=record.label,
        scopes=list(record.scopes),
        status=record.status,
        created_at=record.created_at,
        created_by=record.created_by,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        last_used_at=record.last_used_at,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Issue an ingest API key for one user and domain",
    response_description="The key, returned once and never again",
)
async def issue_api_key(
    payload: Annotated[ApiKeyIssueRequest, Body()],
    principal: PrincipalDep,
    service: ApiKeyServiceDep,
    user_uuid_header: UserUuidHeaderDep = None,
) -> ORJSONResponse:
    """Mint a key for the named emitting domain, bound to a user or to none.

    Two shapes, and the request decides which:

    * **Bound** (default). `x-audit-user-uuid` is required and the key can only
      ever act for that one user, whatever header a later request sends.
    * **Unbound** (`all_users: true`). No user header, and the key takes its
      user from `x-audit-user-uuid` on each request instead - one credential
      for a backend that acts for every user on the platform.

    Write-only by default either way. An emitter needs to store events and
    nothing else, and a key that can also read is a key that can exfiltrate the
    trail it was issued to fill. `audit:erase`, `audit:admin` and
    `audit:cross_user` can never be delegated to an issued key at all, which is
    what keeps an unbound key weaker than the admin credential it resembles.

    The plaintext appears in this response and nowhere else - not in the store,
    not in the logs. Losing it means issuing a new key and revoking this one,
    which is the right habit anyway.

    Raises:
        IngestRejected: the binding and the header disagree, or the requested
            scopes are unknown or not delegable.
    """
    principal.require(Scope.ADMIN)

    if payload.all_users and user_uuid_header is not None:
        raise IngestRejected(
            "an unbound key acts for every user, so do not send "
            "x-audit-user-uuid when requesting all_users"
        )
    if not payload.all_users and user_uuid_header is None:
        raise IngestRejected(
            "x-audit-user-uuid is required to bind a key to one user; "
            "send all_users: true to mint a key for every user instead"
        )

    try:
        minted = await service.issue(
            user_uuid=None if payload.all_users else user_uuid_header,
            domain=payload.domain,
            label=payload.label,
            created_by=principal.audit_identity,
            requested_scopes=tuple(payload.scopes) if payload.scopes else None,
            expires_in_days=payload.expires_in_days,
        )
    except ApiKeyError as exc:
        raise IngestRejected(str(exc)) from exc

    issued = ApiKeyIssued(
        api_key=minted.plaintext,
        hint=build_key_hint(minted.plaintext),
        **_to_summary(minted.record).model_dump(),
    )
    return success(
        issued.model_dump(mode="json"),
        message="API key issued. Store it now - it cannot be retrieved again.",
        status_code=status.HTTP_201_CREATED,
    )


@router.get(
    "",
    summary="List the keys issued to this user",
)
async def list_api_keys(
    principal: PrincipalDep,
    service: ApiKeyServiceDep,
    user_uuid_header: UserUuidDep,
    size: Annotated[int, Query(ge=1, le=API_KEY_LIST_MAX_SIZE)] = 50,
) -> ORJSONResponse:
    """Every key for this user, newest first, revoked ones included.

    One query serves the page; there is no per-key lookup behind it.
    """
    principal.require(Scope.ADMIN)

    records = await service.list_for_user(user_uuid_header, size=size)
    listing = ApiKeyListResponse(keys=[_to_summary(record) for record in records])
    return success(
        listing.model_dump(mode="json"),
        message=f"{len(listing.keys)} key(s).",
    )


@router.delete(
    "/{key_id}",
    summary="Revoke an issued key",
)
async def revoke_api_key(
    key_id: Annotated[str, Path(max_length=64)],
    principal: PrincipalDep,
    service: ApiKeyServiceDep,
    user_uuid_header: UserUuidDep,
) -> ORJSONResponse:
    """Stop a key working, keeping its record.

    Takes effect immediately on this replica and within the cache window on any
    other. Revoking twice is a no-op, so an incident-response retry is safe.

    Raises:
        NotFound: no such key, or it belongs to a different user - the two are
            deliberately indistinguishable, so this endpoint cannot be used to
            discover another user's key ids.
    """
    principal.require(Scope.ADMIN)

    existing = await service.get_for_user(key_id, user_uuid=user_uuid_header)
    if existing is None:
        raise NotFound("No such API key for this user.")

    revoked = await service.revoke(key_id, revoked_by=principal.audit_identity)
    if revoked is None:  # pragma: no cover - the read above already proved it exists
        raise NotFound("No such API key for this user.")

    return success(
        _to_summary(revoked).model_dump(mode="json"),
        message="API key revoked.",
    )
