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
    TENANT_HEADER,
)
from app.core.exceptions import InvalidHeader, ServiceUnavailable
from app.core.security.auth import (
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    Principal,
)
from app.search.api_key_store import ApiKeyRecord
from app.search.routing import InvalidTenantError, TenantRouter
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


def _validated_tenant(tenant_id: str | None) -> str | None:
    """Shape-check a tenant header that may legitimately be absent.

    Absent stays absent: the cross-tenant read paths have no tenant to name,
    and rejecting them here would make the header impossible to omit. When a
    value *is* present it must be well formed, so a malformed id fails once at
    the boundary rather than three layers down in a query builder.

    Shape only. Whether the tenant exists is the calling backend's business:
    it resolved and authorised the tenant before making this call, and this
    service holds no tenant registry to check against.

    Raises:
        InvalidTenantError: a value was sent but is not shaped like a tenant id.
    """
    if tenant_id is None or not tenant_id.strip():
        return None
    return TenantRouter.validate_tenant_id(tenant_id)


def _assert_key_tenant_matches_header(record: ApiKeyRecord, requested: str | None) -> None:
    """An issued key may only act for the tenant it was issued to.

    The header stays legal - every emitter sends it - but it can only agree.
    Naming a different tenant is an attempt to write into someone else's trail,
    so it is refused rather than quietly resolved in the key's favour.

    Raises:
        AuthorizationError: the header names a different tenant.
    """
    if requested is not None and requested != record.tenant_id:
        raise AuthorizationError(
            f"this API key is bound to a different tenant than the {TENANT_HEADER} header names"
        )


async def _principal_from_issued_key(
    service: ApiKeyService | None,
    presented: str,
    *,
    requested_tenant: str | None,
    acting_for: str | None,
    authenticator: Authenticator,
) -> Principal:
    """Authenticate an issued key and build its principal.

    Every failure answers the same way. Whether the key is malformed, unknown,
    revoked, expired or simply mistyped is in the log, not in the response: a
    credential endpoint that distinguishes them is an oracle for guessing.

    Raises:
        AuthenticationError: the key is not usable, for any reason.
        AuthorizationError: it is usable but bound to another tenant.
    """
    if service is None:
        raise AuthenticationError("invalid service API key")

    record = await service.verify(presented)
    if record is None:
        raise AuthenticationError("invalid service API key")

    _assert_key_tenant_matches_header(record, requested_tenant)
    return authenticator.issued_key_principal(
        key_id=record.key_id,
        domain=record.domain,
        tenant_id=record.tenant_id,
        scopes=to_scopes(record),
        on_behalf_of=acting_for,
    )


async def current_principal(
    request: Request,
    api_key: Annotated[str | None, Header(alias=API_KEY_HEADER)] = None,
    tenant_header: Annotated[str | None, Header(alias=TENANT_HEADER)] = None,
    on_behalf_of: Annotated[str | None, Header(alias=ON_BEHALF_HEADER)] = None,
) -> Principal:
    """Authenticate the caller.

    Two kinds of credential arrive in `x-api-key`, and which one it is decides
    where the tenant comes from:

    * **An env-configured key** (`SERVICE_API_KEYS`). The admin plane: every
      scope, not bound to a tenant, so `x-audit-tenant-id` names the tenant and
      is trusted as given after a shape check. The caller in front of this
      service resolved and authorised that tenant already.
    * **An issued key** (`evcaud_...`). Bound to one tenant when it was minted,
      so the tenant comes from the key and the header may only agree with it.
      Its scopes are whatever that key was granted - normally write only - and
      its `subject` is the verified domain it was issued to rather than the
      unchecked `x-service-name` claim.

    Env keys are tried first: that comparison is in memory and costs nothing,
    while an issued key falls through to one cached lookup.

    Raises:
        AuthenticationError: no key was presented, or it is usable as neither
            kind of credential.
        AuthorizationError: an issued key was used for another tenant.
        InvalidTenantError: a tenant header was sent but is malformed.
    """
    if not api_key:
        raise AuthenticationError("no credentials supplied")

    container = _container(request)
    requested_tenant = _validated_tenant(tenant_header)
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
            tenant_id=requested_tenant,
            on_behalf_of=acting_for,
        )
    else:
        principal = await _principal_from_issued_key(
            container.api_keys,
            api_key,
            requested_tenant=requested_tenant,
            acting_for=acting_for,
            authenticator=container.authenticator,
        )

    # Stashed so the error handlers and access log can attribute a failure
    # without re-authenticating.
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


async def tenant_id_header(
    tenant_header: Annotated[str | None, Header(alias=TENANT_HEADER)] = None,
) -> str | None:
    """The tenant this call acts for, when one was named.

    For the two routes that can legitimately run without a tenant - search and
    aggregate under `cross_tenant=true`. Every other tenant-scoped route takes
    `TenantIdDep` instead and refuses to run without a tenant.

    Optional here rather than required so the failure surfaces from the
    authorisation layer with an explanatory message, instead of as a bare 422
    from request validation.
    """
    return tenant_header


TenantHeaderDep = Annotated[str | None, Depends(tenant_id_header)]


async def require_tenant_id(
    tenant_header: Annotated[str | None, Header(alias=TENANT_HEADER)] = None,
) -> str:
    """The tenant this call acts for. Mandatory, validated, normalised.

    Applied to every route that touches one tenant's records, so the tenant is
    settled at the API boundary: a caller that forgets the header gets one clear
    400 naming the header, not an ingest rejection from one route and an
    authorisation error from the next.

    Declared with a `None` default and checked in the body rather than as a
    required FastAPI header, because a bare 422 listing `x-audit-tenant-id` as a
    missing field explains far less than the message below.

    Raises:
        InvalidTenantError: the header is absent, blank, or malformed.
    """
    if tenant_header is None or not tenant_header.strip():
        raise InvalidTenantError(
            f"the {TENANT_HEADER} header is required: it names the tenant this "
            "call acts for, and the API key is not bound to a tenant"
        )
    return TenantRouter.validate_tenant_id(tenant_header)


TenantIdDep = Annotated[str, Depends(require_tenant_id)]


async def issuer_id_header(
    issuer_header: Annotated[str | None, Header(alias=ISSUER_HEADER)] = None,
) -> str | None:
    """The issuer (sub-tenant) this call acts within, when one was named.

    Optional, and a *default* rather than an override: an event that carries its
    own `issuer_id` keeps it, because a batch can legitimately span issuers
    within one tenant. Unlike the tenant, this is a descriptive field and not a
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
