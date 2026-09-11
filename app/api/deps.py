"""FastAPI dependency wiring.

Long-lived collaborators (the Elasticsearch client, the Redis pool, the cipher)
are built once during startup and stashed on `app.state`. Building them per
request would create a connection pool per request, which is the classic way to
make a service fall over under load.

Request-scoped objects (the principal) are resolved per call, because they depend
on the credential presented.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, Request

from app.core.config import Settings, get_settings
from app.core.constants import (
    API_KEY_HEADER,
    ISSUER_HEADER,
    MAX_IDENTITY_HEADER_LENGTH,
    ON_BEHALF_HEADER,
    SERVICE_NAME_HEADER,
    USER_UUID_HEADER,
)
from app.core.exceptions import InvalidHeader, ServiceUnavailable
from app.core.security.auth import (
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    Principal,
)
from app.search.api_key_store import ApiKeyRecord
from app.search.routing import InvalidUserUuidError, UserRouter
from app.services.api_key_service import ApiKeyService, to_scopes
from app.services.compliance_service import ErasureService, IntegrityService
from app.services.ingest_service import IngestService
from app.services.query_service import QueryService


def settings_dep() -> Settings:
    """Request-scoped settings accessor (cached process-wide via lru_cache)."""
    return get_settings()


SettingsDep = Annotated[Settings, Depends(settings_dep)]


# ---------------------------------------------------------------------------
# Container access
# ---------------------------------------------------------------------------
def _container(request: Request) -> ServiceContainer:
    """Fetch the startup-built container from ``app.state``."""
    container = getattr(request.app.state, "container", None)
    if container is None:  # pragma: no cover - only on a misconfigured app
        raise RuntimeError("service container missing; the app did not start correctly")
    return container  # type: ignore[no-any-return]


def get_ingest_service(request: Request) -> IngestService:
    """Resolve the shared ingest service for this request."""
    return _container(request).ingest


def get_query_service(request: Request) -> QueryService:
    """Resolve the shared query service for this request."""
    return _container(request).query


def get_integrity_service(request: Request) -> IntegrityService:
    """Resolve the hash-chain integrity verifier."""
    return _container(request).integrity


def get_erasure_service(request: Request) -> ErasureService:
    """Resolve the crypto-shredding erasure service."""
    return _container(request).erasure


def get_api_key_service(request: Request) -> ApiKeyService:
    """Resolve issued-key management.

    Raises:
        ServiceUnavailable: `API_KEY_PEPPER` is unset, so keys cannot be minted
            or verified. The message names the setting, because the fix is one
            line of configuration and a restart.
    """
    service = _container(request).api_keys
    if service is None:
        raise ServiceUnavailable(
            "API key management is not configured: set API_KEY_PEPPER and restart. "
            "Until then only the keys in SERVICE_API_KEYS authenticate."
        )
    return service


IngestServiceDep = Annotated[IngestService, Depends(get_ingest_service)]
QueryServiceDep = Annotated[QueryService, Depends(get_query_service)]
IntegrityServiceDep = Annotated[IntegrityService, Depends(get_integrity_service)]
ErasureServiceDep = Annotated[ErasureService, Depends(get_erasure_service)]
ApiKeyServiceDep = Annotated[ApiKeyService, Depends(get_api_key_service)]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def _validated_identity(value: str | None, *, header: str) -> str | None:
    """Normalise an identity header, or None when it was not sent.

    Raises:
        InvalidHeader: the value is longer than the field it is recorded in.
    """
    if value is None or not value.strip():
        return None
    candidate = value.strip()
    if len(candidate) > MAX_IDENTITY_HEADER_LENGTH:
        raise InvalidHeader(f"{header} must be at most {MAX_IDENTITY_HEADER_LENGTH} characters")
    return candidate


def _validated_user(user_uuid: str | None) -> str | None:
    """Shape-check a user header that may legitimately be absent.

    Absent stays absent: the cross-user read paths have no user to name,
    and rejecting them here would make the header impossible to omit. When a
    value *is* present it must be well formed, so a malformed id fails once at
    the boundary rather than three layers down in a query builder.

    Shape only. Whether the user exists is the calling backend's business:
    it resolved and authorised the user before making this call, and this
    service holds no user registry to check against.

    Raises:
        InvalidUserUuidError: a value was sent but is not shaped like a user uuid.
    """
    if user_uuid is None or not user_uuid.strip():
        return None
    return UserRouter.validate_user_uuid(user_uuid)


def _resolve_key_user(record: ApiKeyRecord, requested: str | None) -> str:
    """Settle which user an issued key is acting for on this request.

    Two kinds of key, and the difference is the point of binding at all:

    * **Bound** (`record.user_uuid` set). The key decides. The header stays
      legal - every emitter sends it - but it can only agree. Naming a
      different user is an attempt to write into someone else's trail, so it
      is refused rather than quietly resolved in the key's favour.
    * **Unbound** (`record.user_uuid` is None). The header decides, so a single
      credential serves a backend that acts for every user. The header is then
      mandatory: without it there is no user, and an event with no user cannot
      be filed or filtered.

    Raises:
        AuthorizationError: a bound key was used for a different user.
        InvalidUserUuidError: an unbound key was used with no user header.
    """
    # `record.user_uuid is None` rather than `record.is_unbound`: same
    # condition, but this form narrows the type for the return below.
    if record.user_uuid is None:
        if requested is None:
            raise InvalidUserUuidError(
                f"this API key is not bound to a user, so {USER_UUID_HEADER} is "
                "required to name the user whose trail this call acts on"
            )
        return requested

    if requested is not None and requested != record.user_uuid:
        raise AuthorizationError(
            f"this API key is bound to a different user than the {USER_UUID_HEADER} header names"
        )
    return record.user_uuid


async def _principal_from_issued_key(
    service: ApiKeyService | None,
    presented: str,
    *,
    requested_user: str | None,
    acting_for: str | None,
    authenticator: Authenticator,
) -> Principal:
    """Authenticate an issued key and build its principal.

    Every failure answers the same way. Whether the key is malformed, unknown,
    revoked, expired or simply mistyped is in the log, not in the response: a
    credential endpoint that distinguishes them is an oracle for guessing.

    Raises:
        AuthenticationError: the key is not usable, for any reason.
        AuthorizationError: it is usable but bound to another user.
        InvalidUserUuidError: it is unbound and no user header was sent.
    """
    if service is None:
        raise AuthenticationError("invalid service API key")

    record = await service.verify(presented)
    if record is None:
        raise AuthenticationError("invalid service API key")

    return authenticator.issued_key_principal(
        key_id=record.key_id,
        domain=record.domain,
        user_uuid=_resolve_key_user(record, requested_user),
        scopes=to_scopes(record),
        on_behalf_of=acting_for,
    )


async def current_principal(
    request: Request,
    api_key: Annotated[str | None, Header(alias=API_KEY_HEADER)] = None,
    user_uuid_header: Annotated[str | None, Header(alias=USER_UUID_HEADER)] = None,
    on_behalf_of: Annotated[str | None, Header(alias=ON_BEHALF_HEADER)] = None,
) -> Principal:
    """Authenticate the caller.

    Two kinds of credential arrive in `x-api-key`, and which one it is decides
    where the user comes from:

    * **An env-configured key** (`SERVICE_API_KEYS`). The admin plane: every
      scope, not bound to a user, so `x-audit-user-uuid` names the user and
      is trusted as given after a shape check. The caller in front of this
      service resolved and authorised that user already.
    * **An issued key** (`evcaud_...`). Bound to one user when it was minted,
      so the user comes from the key and the header may only agree with it.
      Its scopes are whatever that key was granted - normally write only - and
      its `subject` is the verified domain it was issued to rather than the
      unchecked `x-service-name` claim.

    Env keys are tried first: that comparison is in memory and costs nothing,
    while an issued key falls through to one cached lookup.

    Raises:
        AuthenticationError: no key was presented, or it is usable as neither
            kind of credential.
        AuthorizationError: an issued key was used for another user.
        InvalidUserUuidError: a user header was sent but is malformed.
    """
    if not api_key:
        raise AuthenticationError("no credentials supplied")

    container = _container(request)
    requested_user = _validated_user(user_uuid_header)
    # The human this call is for. Stamped onto every event the call ingests
    # (`actor.on_behalf_of`), so a service-mediated write stays attributable to
    # a person and not just to the service account.
    acting_for = _validated_identity(on_behalf_of, header=ON_BEHALF_HEADER)

    if container.authenticator.verify_api_key(api_key):
        principal = container.authenticator.service_principal(
            # The calling service names itself for attribution. It is
            # unverified, so it is recorded as a claim rather than trusted for
            # authorisation - the API key is what grants access.
            service_name=request.headers.get(SERVICE_NAME_HEADER, "unknown-service"),
            user_uuid=requested_user,
            on_behalf_of=acting_for,
        )
    else:
        principal = await _principal_from_issued_key(
            container.api_keys,
            api_key,
            requested_user=requested_user,
            acting_for=acting_for,
            authenticator=container.authenticator,
        )

    # Stashed so the error handlers and access log can attribute a failure
    # without re-authenticating.
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


async def user_uuid_header(
    user_uuid_header: Annotated[str | None, Header(alias=USER_UUID_HEADER)] = None,
) -> str | None:
    """The user this call acts for, when one was named.

    For the two routes that can legitimately run without a user - search and
    aggregate under `cross_user=true`. Every other user-scoped route takes
    `UserUuidDep` instead and refuses to run without a user.

    Optional here rather than required so the failure surfaces from the
    authorisation layer with an explanatory message, instead of as a bare 422
    from request validation.
    """
    return user_uuid_header


UserUuidHeaderDep = Annotated[str | None, Depends(user_uuid_header)]


async def require_user_uuid(
    user_uuid_header: Annotated[str | None, Header(alias=USER_UUID_HEADER)] = None,
) -> str:
    """The user this call acts for. Mandatory, validated, normalised.

    Applied to every route that touches one user's records, so the user is
    settled at the API boundary: a caller that forgets the header gets one clear
    400 naming the header, not an ingest rejection from one route and an
    authorisation error from the next.

    Declared with a `None` default and checked in the body rather than as a
    required FastAPI header, because a bare 422 listing `x-audit-user-uuid` as a
    missing field explains far less than the message below.

    Raises:
        InvalidUserUuidError: the header is absent, blank, or malformed.
    """
    if user_uuid_header is None or not user_uuid_header.strip():
        raise InvalidUserUuidError(
            f"the {USER_UUID_HEADER} header is required: it names the user this "
            "call acts for, and the API key is not bound to a user"
        )
    return UserRouter.validate_user_uuid(user_uuid_header)


UserUuidDep = Annotated[str, Depends(require_user_uuid)]


async def issuer_id_header(
    issuer_header: Annotated[str | None, Header(alias=ISSUER_HEADER)] = None,
) -> str | None:
    """The issuer (sub-user) this call acts within, when one was named.

    Optional, and a *default* rather than an override: an event that carries its
    own `issuer_id` keeps it, because a batch can legitimately span issuers
    within one user. Unlike the user, this is a descriptive field and not a
    boundary - reads are never scoped by it unless the caller asks - so a wrong
    value mislabels a record without exposing anything.

    Raises:
        InvalidHeader: the value is longer than the field it is recorded in.
    """
    return _validated_identity(issuer_header, header=ISSUER_HEADER)


IssuerHeaderDep = Annotated[str | None, Depends(issuer_id_header)]


# Imported last to avoid a circular import: the container imports the services,
# which import the schemas, which do not import this module.
from app.api.container import ServiceContainer  # noqa: E402
