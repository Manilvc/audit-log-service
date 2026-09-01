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
from app.core.security.auth import (
    API_KEY_HEADER,
    ON_BEHALF_HEADER,
    TENANT_HEADER,
    AuthenticationError,
    Authenticator,
    Principal,
)
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


IngestServiceDep = Annotated[IngestService, Depends(get_ingest_service)]
QueryServiceDep = Annotated[QueryService, Depends(get_query_service)]
IntegrityServiceDep = Annotated[IntegrityService, Depends(get_integrity_service)]
ErasureServiceDep = Annotated[ErasureService, Depends(get_erasure_service)]


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
async def current_principal(
    request: Request,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    api_key: Annotated[str | None, Header(alias=API_KEY_HEADER)] = None,
    tenant_header: Annotated[str | None, Header(alias=TENANT_HEADER)] = None,
    on_behalf_of: Annotated[str | None, Header(alias=ON_BEHALF_HEADER)] = None,
) -> Principal:
    """Authenticate the caller.

    The API key is checked first. It is the machine path carrying the bulk of
    traffic, and a constant-time key comparison is far cheaper than JWT
    signature verification.

    Both credentials being present is rejected rather than resolved by
    precedence: it is ambiguous which identity should be recorded in the audit
    trail, and guessing would make attribution unreliable.

    Raises:
        AuthenticationError: no credential, or two conflicting ones.
    """
    authenticator: Authenticator = _container(request).authenticator

    has_bearer = bool(authorization and authorization.startswith("Bearer "))
    has_key = bool(api_key)

    if has_key and has_bearer:
        raise AuthenticationError(
            "present either x-api-key or a Bearer token, not both: "
            "the audit trail must attribute this call to one identity"
        )

    if has_key:
        if not authenticator.verify_api_key(api_key):
            raise AuthenticationError("invalid service API key")
        principal = authenticator.service_principal(
            # The calling service names itself for attribution. It is
            # unverified, so it is recorded as a claim rather than trusted for
            # authorisation - the API key is what grants access.
            service_name=request.headers.get("x-service-name", "unknown-service"),
            tenant_id=tenant_header,
            on_behalf_of=on_behalf_of,
        )
    elif has_bearer and authorization is not None:
        # The `and` is a real narrowing rather than an assert: asserts vanish
        # under `python -O`, which would turn this into a TypeError on the
        # authentication path.
        principal = authenticator.verify_jwt(authorization[7:].strip())
    else:
        raise AuthenticationError("no credentials supplied")

    # Stashed so the error handlers and access log can attribute a failure
    # without re-authenticating.
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


async def tenant_id_header(
    tenant_header: Annotated[str | None, Header(alias=TENANT_HEADER)] = None,
) -> str | None:
    """The tenant a service principal is acting for, if it named one."""
    return tenant_header


TenantHeaderDep = Annotated[str | None, Depends(tenant_id_header)]


# Imported last to avoid a circular import: the container imports the services,
# which import the schemas, which do not import this module.
from app.api.container import ServiceContainer  # noqa: E402
