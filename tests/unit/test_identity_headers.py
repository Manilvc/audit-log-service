"""The request identity headers: tenant, issuer, and the user behind the call.

`x-audit-tenant-id` is the whole tenant boundary - the API key is not bound to a
tenant - so most of this file guards the two ways that boundary can fail at the
edge: a call that names no tenant must not proceed, and a call that names a
malformed one must not reach an index name.

Existence is deliberately out of scope here as well as in the code: the calling
backend has already resolved and authorised the tenant. What must hold is that
*something* well formed was named, and that the same value is what every
downstream scope is built from.

`x-audit-issuer-id` and `x-audit-on-behalf-of` are attribution rather than
boundary, and are bounded by the width of the field they are stored in - an
over-long value must fail the request once, not reject 500 events one by one.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.api.deps import (
    _validated_identity,
    _validated_tenant,
    current_principal,
    get_erasure_service,
    get_ingest_service,
    get_integrity_service,
    get_query_service,
    issuer_id_header,
    require_tenant_id,
)
from app.api.openapi import _TENANT_REQUIRED_OPERATIONS, build_openapi
from app.core.config import Settings, get_settings
from app.core.exceptions import InvalidHeader
from app.core.security.auth import ON_BEHALF_HEADER, AuthorizationError, Principal
from app.domain.enums import ActorType, Scope
from app.schemas.api import SearchResponse
from app.search.routing import InvalidTenantError, TenantRouter
from app.services.query_service import QueryService

#: Values Elasticsearch or a URL path would choke on, plus the traversal
#: attempts. Each one must be refused before it can reach an index name.
MALFORMED = [
    "*",
    "audit-*",
    "tenant a",
    "../etc",
    "a,b",
    "_leading-underscore",
    "-leading-dash",
    'quote"d',
    "a" * 64,
]


def _principal(tenant_id: str | None = None) -> Principal:
    return Principal(
        subject="everycred-backend",
        actor_type=ActorType.SERVICE,
        tenant_id=tenant_id,
        scopes=frozenset(Scope),
    )


# ---------------------------------------------------------------------------
# Required header (every tenant-scoped route)
# ---------------------------------------------------------------------------
async def test_required_header_returns_a_well_formed_tenant_id() -> None:
    assert await require_tenant_id("7f3c1b9a-0d21-4c8e-9b77-2a1f5e6c8d90") == (
        "7f3c1b9a-0d21-4c8e-9b77-2a1f5e6c8d90"
    )


async def test_required_header_is_normalised_before_use() -> None:
    """Whitespace is stripped, so " t1" and "t1" cannot become two tenants.

    A proxy or a hand-written client adding a space would otherwise write into
    a second, near-identical partition that the tenant can never read back.
    """
    assert await require_tenant_id("  tenant-a  ") == "tenant-a"


@pytest.mark.parametrize("absent", [None, "", "   ", "\t"])
async def test_required_header_refuses_a_call_that_names_no_tenant(absent: str | None) -> None:
    """400 naming the header, rather than a failure three layers down.

    The API key grants every scope, so a request with no tenant is not a
    harmless no-op: it is a caller who has not said whose trail they are about
    to write to or read.
    """
    with pytest.raises(InvalidTenantError, match="x-audit-tenant-id"):
        await require_tenant_id(absent)


@pytest.mark.parametrize("hostile", MALFORMED)
async def test_required_header_refuses_a_malformed_tenant_id(hostile: str) -> None:
    with pytest.raises(InvalidTenantError):
        await require_tenant_id(hostile)


# ---------------------------------------------------------------------------
# Optional header (cross-tenant reads, health, admin)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("absent", [None, "", "   "])
def test_optional_header_treats_blank_as_absent(absent: str | None) -> None:
    """Blank is None, not "".

    An empty string would be a falsy tenant id travelling on the principal, and
    every downstream `if not tenant_id` check would then have to agree about it.
    """
    assert _validated_tenant(absent) is None


def test_optional_header_still_shape_checks_a_value_it_was_given() -> None:
    """Optional is about presence, never about validity."""
    assert _validated_tenant(" tenant-a ") == "tenant-a"
    with pytest.raises(InvalidTenantError):
        _validated_tenant("audit-*")


# ---------------------------------------------------------------------------
# Attribution headers: issuer, and the user a service acts for
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("absent", [None, "", "   "])
async def test_issuer_header_is_optional(absent: str | None) -> None:
    """Most events have no sub-tenant behind them."""
    assert await issuer_id_header(absent) is None


async def test_issuer_header_is_normalised() -> None:
    assert await issuer_id_header("  issuer-77  ") == "issuer-77"


async def test_issuer_header_longer_than_the_field_is_refused() -> None:
    """400 naming the header, rather than a truncated issuer on the record.

    The alternative - store what fits - writes a subtly wrong id into an
    immutable log, which is worse than making the caller fix the call.
    """
    with pytest.raises(InvalidHeader, match="x-audit-issuer-id"):
        await issuer_id_header("i" * 65)


def test_acting_user_header_is_bounded_by_the_field_it_lands_in() -> None:
    """Checked once per request, not once per event.

    `actor.on_behalf_of` is a 64-character field. Without this check a long
    header would fail validation inside `to_domain` and reject every event in
    the batch individually, with an error that never names the header.
    """
    assert _validated_identity(f"  {'u' * 36}  ", header=ON_BEHALF_HEADER) == "u" * 36
    assert _validated_identity("   ", header=ON_BEHALF_HEADER) is None
    with pytest.raises(InvalidHeader, match=ON_BEHALF_HEADER):
        _validated_identity("u" * 65, header=ON_BEHALF_HEADER)


# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------
@pytest.fixture
def query(settings: Settings, router: TenantRouter) -> QueryService:
    """A query service with only what `resolve_scope` touches.

    Scope resolution is pure - it reads the router and the principal - so the
    Elasticsearch and Redis collaborators stay unbuilt rather than faked.
    """
    return QueryService(
        settings=settings,
        repository=None,  # type: ignore[arg-type]
        router=router,
        cipher=None,  # type: ignore[arg-type]
        queue=None,  # type: ignore[arg-type]
    )


def test_tenant_scoped_read_without_a_tenant_is_a_bad_request(query: QueryService) -> None:
    """400, not 403: the caller may read, they just did not say whose trail.

    Reachable only from search and aggregate with `cross_tenant=false`, since
    every other read takes the required dependency and fails before this.
    """
    with pytest.raises(InvalidTenantError, match="x-audit-tenant-id"):
        query.resolve_scope(_principal(), requested_tenant_id=None)


def test_cross_tenant_read_needs_no_tenant_but_needs_the_scope(query: QueryService) -> None:
    scope = query.resolve_scope(_principal(), cross_tenant=True)
    assert scope.cross_tenant and scope.tenant_id is None

    without_scope = Principal(
        subject="everycred-backend",
        actor_type=ActorType.SERVICE,
        tenant_id=None,
        scopes=frozenset({Scope.READ}),
    )
    with pytest.raises(AuthorizationError, match="audit:cross_tenant"):
        query.resolve_scope(without_scope, cross_tenant=True)


def test_header_wins_over_the_principal_but_both_are_validated(query: QueryService) -> None:
    """The per-request header is authoritative; the principal is the fallback.

    A service key writes for many tenants, so the tenant belongs to the request
    rather than to the credential.
    """
    scope = query.resolve_scope(_principal("tenant-b"), requested_tenant_id="tenant-a")
    assert scope.tenant_id == "tenant-a"

    with pytest.raises(InvalidTenantError):
        query.resolve_scope(_principal(), requested_tenant_id="audit-*")


# ---------------------------------------------------------------------------
# Documentation cannot drift from the routes
# ---------------------------------------------------------------------------
class _StubQuery:
    """Enough query service for the two routes where the tenant is optional."""

    async def search(self, *args: Any, **kwargs: Any) -> SearchResponse:
        return SearchResponse(events=[], cursor=None, total=None, took_ms=0)


@pytest.fixture
def client() -> Iterator[TestClient]:
    """The real app, with the container-backed dependencies stubbed out.

    `current_principal` is overridden because authentication is not what is
    under test here - the tenant dependency is, and it must be the real one, so
    it is deliberately left alone. Instantiated without entering the context
    manager, so no lifespan runs and nothing dials Elasticsearch or Redis.
    """
    from app.main import app

    app.dependency_overrides[current_principal] = lambda: _principal("tenant-a")
    app.dependency_overrides[get_query_service] = _StubQuery
    app.dependency_overrides[get_ingest_service] = lambda: None
    app.dependency_overrides[get_integrity_service] = lambda: None
    app.dependency_overrides[get_erasure_service] = lambda: None
    try:
        yield TestClient(app, raise_server_exceptions=False)
    finally:
        app.dependency_overrides.clear()


def _refuses_without_a_tenant(client: TestClient, path: str, method: str) -> bool:
    """Call one operation with no tenant header and report whether it refused.

    The body is deliberately empty: the tenant dependency resolves before the
    handler runs, so a route that requires a tenant answers 400 without ever
    looking at the payload.
    """
    url = path.replace("{event_id}", "evt_probe").replace("{tenant_id}", "tenant-a")
    response = client.request(method.upper(), url, json=None if method == "get" else {})
    return response.status_code == 400 and "x-audit-tenant-id" in response.text


def test_every_route_that_needs_a_tenant_refuses_a_call_without_one(
    client: TestClient,
) -> None:
    """Behaviour, not annotation: each of these answers 400, body unread."""
    for path, method in sorted(_TENANT_REQUIRED_OPERATIONS):
        assert _refuses_without_a_tenant(client, path, method), (
            f"{method.upper()} {path} accepted a call that named no tenant"
        )


def test_openapi_marks_the_header_required_exactly_where_the_routes_do(
    client: TestClient,
) -> None:
    """`_TENANT_REQUIRED_OPERATIONS` is curated by hand, so it can go stale.

    FastAPI cannot infer the requirement - the dependency declares a `None`
    default so the error stays explanatory - which leaves the schema and the
    routes to be kept in step. Every documented operation is probed, so adding
    a tenant-scoped route and forgetting the constant fails here rather than
    silently telling every reader the header is optional.
    """
    from app.main import app

    app.openapi_schema = None
    schema = build_openapi(app, get_settings())
    app.openapi_schema = None

    documented_required: set[tuple[str, str]] = set()
    actually_required: set[tuple[str, str]] = set()
    for path, operations in schema["paths"].items():
        for method, operation in operations.items():
            if not isinstance(operation, dict):
                continue
            if any(
                parameter.get("in") == "header"
                and parameter.get("name") == "x-audit-tenant-id"
                and parameter.get("required")
                for parameter in operation.get("parameters", [])
            ):
                documented_required.add((path, method))
            if _refuses_without_a_tenant(client, path, method):
                actually_required.add((path, method))

    assert actually_required == documented_required
    assert documented_required == set(_TENANT_REQUIRED_OPERATIONS)
