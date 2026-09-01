"""FastAPI application factory.

Assembles middleware, routers, exception handlers and the service container,
then runs idempotent Elasticsearch bootstrap and WORM-archive verification on
startup. The CLI (``audit-service serve``) is the supported entrypoint;
``app`` at module level exists for tooling that expects ``uvicorn app.main:app``.

Lifecycle
---------
1. Configure structured logging from settings.
2. Build the ``ServiceContainer`` (ES, Redis, cipher, services).
3. Mount CORS (explicit origins only), security/rate-limit middleware, routers.
4. On startup: bootstrap ILM/templates/streams, verify Object Lock when archive
   is enabled, stash the container on ``app.state``.
5. On shutdown: close clients cleanly so connections are not leaked across reloads.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api.container import build_container
from app.api.docs_ui import redoc_html
from app.api.openapi import build_openapi
from app.api.router import ops_router, v1_router
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware.stack import (
    REDOC_CSP,
    SWAGGER_CSP,
    BodyLimitMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.responses import ORJSONResponse
from app.search.bootstrap import bootstrap_cluster

logger = get_logger(__name__)

# Raw string: the shell examples end lines with a backslash continuation, and
# in a normal literal Python reads backslash-newline as a line join and eats
# the newline - collapsing every curl example onto one unreadable line.
_DESCRIPTION = r"""
Tamper-evident, multi-tenant audit log service for the EveryCRED DCS platform.

Every security-relevant action across the platform - credential issuance,
revocation, login, permission change, consent withdrawal, configuration edit -
lands here as one canonical event, in one queryable place, with cryptographic
proof it has not been altered.

**Storage** - Elasticsearch 9.x data streams, hybrid tenant isolation (a shared
stream by default, dedicated streams for high-volume tenants), with a durable
Redis Streams buffer in front and an immutable S3 Object Lock archive behind.

**Tamper evidence** - every event carries a SHA-256 hash chained to its
predecessor within its tenant's chain, and chain heads are periodically
notarised into WORM storage. Modification, deletion, reordering and insertion
are all detectable, and distinguishable from each other.

**Privacy** - personal data is encrypted per data subject and never indexed. An
erasure request destroys the subject's key rather than the record, so GDPR
Art. 17 and DPDP s.12 are honoured without breaking the immutability that
SOC 2, ISO 27001 and HIPAA require.

# Getting started

Emit one event, then read it back:

```bash
# 1. Write. Returns 202 - the event is queued, not yet searchable.
curl -X POST "$AUDIT_URL/v1/audit/events" \
  -H "x-api-key: $AUDIT_API_KEY" \
  -H "x-audit-tenant-id: $TENANT_ID" \
  -H "content-type: application/json" \
  -d '{"events":[{"action":"user.login","outcome":"success",
        "actor":{"type":"user","id":"u_123"},
        "service_name":"everycred-backend",
        "event_id":"evt_login_u123_20260831T091422Z"}]}'

# 2. Read. Allow ~1s for the worker to drain the queue into Elasticsearch.
curl -X POST "$AUDIT_URL/v1/audit/events/search" \
  -H "x-api-key: $AUDIT_API_KEY" \
  -H "x-audit-tenant-id: $TENANT_ID" \
  -H "content-type: application/json" \
  -d '{"start":"now-1h","end":"now","size":20}'
```

# Authentication

Two credentials are accepted and they are **mutually exclusive** - a request
carrying both is rejected rather than resolved by precedence, because the trail
has to attribute the call to exactly one identity.

| | Service API key | Platform JWT |
|---|---|---|
| Header | `x-api-key` | `Authorization: Bearer <token>` |
| For | emitting services, machine readers | human callers from the platform UI |
| Tenant | **you must send** `x-audit-tenant-id` | taken from the token claims |
| Scopes | full ingest + read | from the token claims (listed below) |

JWT scopes: `audit:read`, `audit:write`, `audit:export`, `audit:erase`,
`audit:verify`, `audit:admin`, `audit:cross_tenant`.

A service key is not bound to a tenant, so `x-audit-tenant-id` is what tells the
service which tenant the call acts for. On ingest, an event whose body
`tenant_id` disagrees with that header is rejected rather than silently
resolved. When a backend acts for a person, also send `x-audit-on-behalf-of`,
so the trail attributes the action to the human rather than the service account.

<SecurityDefinitions />

# Conventions

**Every response uses the platform envelope.** A successful call returns
`{"status": "success", "data": {...}, "message": "..."}`; a failure returns
`{"status": "fail", "data": null, "message": "..."}` with the HTTP status
carrying the category. Read `data`, not the top level.

**Writes are asynchronous.** `POST /v1/audit/events` returns `202 Accepted`:
the batch is durably queued and lands in Elasticsearch about a second later.
Do not write a read-after-write assertion against it.

**Send `event_id`.** It is the idempotency key. The Elasticsearch write is
keyed on it with `op_type: create`, so a retry after a timeout is safe and a
duplicate is rejected rather than indexed twice. Without one, a retried batch
becomes duplicate audit records.

**Partial success is normal.** One malformed event does not reject the batch -
`rejected` and `errors` report the index of each failed event within the batch
you sent.

**Search, not fetch.** Reads are tenant-filtered searches, so an event id from
another tenant returns `404` rather than the record. Pagination is
cursor-based: pass the `cursor` from the previous response, and page 500 costs
what page 1 costs.

**Errors.** `401` no or ambiguous credentials, `403` missing scope or another
tenant's data, `422` schema validation, `429` rate limited - reads are capped
low because reads are the sensitive surface, ingest is capped high because
throttling ingest means dropping evidence.
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI application.

    Args:
        settings: optional override for tests; production always loads from env.
    """
    resolved = settings or get_settings()
    configure_logging(
        level="DEBUG" if resolved.DEBUG else "INFO",
        json_output=resolved.ENVIRONMENT.value != "local",
    )

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Start and stop long-lived resources."""
        container = build_container(resolved)
        app.state.container = container
        logger.info(
            "service_starting",
            environment=resolved.ENVIRONMENT.value,
            pii_encryption=container.cipher.enabled,
            archive_enabled=container.archive.enabled,
            dedicated_tenants=len(resolved.dedicated_tenant_set),
        )

        # Bootstrap failures are logged but do not abort startup: a replica that
        # cannot reach Elasticsearch yet must still come up and buffer writes,
        # which is the whole point of the queue. Readiness reports the problem.
        try:
            await bootstrap_cluster(container.es, resolved, container.router)
        except Exception as exc:
            logger.error("cluster_bootstrap_failed", error=str(exc))

        try:
            await container.queue.ensure_groups()
        except Exception as exc:
            logger.error("queue_group_setup_failed", error=str(exc))

        # The WORM check is a *warning*, not a hard failure. It would be wrong
        # to refuse to start - that would stop audit collection entirely - but a
        # misconfigured bucket silently produces deletable "immutable" evidence,
        # so it must be impossible to miss in the logs.
        if container.archive.enabled:
            try:
                await container.archive.verify_bucket()
                logger.info("worm_archive_verified")
            except Exception as exc:
                logger.error(
                    "worm_archive_misconfigured",
                    error=str(exc),
                    impact=(
                        "archived audit segments are NOT immutable; "
                        "tamper-evidence guarantees are reduced"
                    ),
                )

        try:
            yield
        finally:
            logger.info("service_stopping")
            await container.aclose()

    app = FastAPI(
        title="EveryCRED Audit Log Service",
        description=_DESCRIPTION,
        version="1.0.0",
        default_response_class=ORJSONResponse,
        lifespan=lifespan,
        # Schema endpoints are off in production: the API shape describes the
        # whole platform's activity model and is reconnaissance value.
        docs_url="/docs" if resolved.ENABLE_DOCS else None,
        # ReDoc is served by `_install_docs` instead: the stock page pulls its
        # bundle and fonts from third-party CDNs, which this one does not.
        redoc_url=None,
        openapi_url="/openapi.json" if resolved.ENABLE_DOCS else None,
    )

    # The generated schema documents the models but not how to authenticate
    # against them; `build_openapi` supplies the security schemes, tag prose and
    # examples that turn it into something a developer can work from.
    app.openapi = lambda: build_openapi(app, resolved)  # type: ignore[method-assign]

    _install_middleware(app, resolved)
    _install_docs(app, resolved)
    register_exception_handlers(app)

    app.include_router(v1_router, prefix=resolved.API_V1_PREFIX)
    app.include_router(ops_router)

    return app


def _install_docs(app: FastAPI, settings: Settings) -> None:
    """Serve the vendored ReDoc bundle and the branded reference page.

    Nothing is mounted when docs are disabled, which is what production
    enforces: the static mount would otherwise be a live route advertising that
    a documentation UI exists on a deployment that deliberately hides its
    schema.
    """
    if not settings.ENABLE_DOCS:
        return

    static_dir = Path(__file__).resolve().parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/redoc", include_in_schema=False)
    async def redoc() -> HTMLResponse:
        """The API reference, rendered from the schema this service publishes."""
        return HTMLResponse(
            redoc_html(
                openapi_url=app.openapi_url or "/openapi.json",
                title=app.title,
                script_url="/static/redoc.standalone.js",
                environment=settings.ENVIRONMENT.value,
                swagger_url=app.docs_url,
            )
        )


def _install_middleware(app: FastAPI, settings: Settings) -> None:
    """Install middleware.

    Starlette applies `add_middleware` in reverse, so the last registered runs
    outermost. Registering in reverse of the intended execution order gives:
    request context -> security headers -> body limit -> rate limit -> CORS.
    """
    if settings.CORS_ALLOW_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.CORS_ALLOW_ORIGINS,
            allow_credentials=True,
            # Only the methods this API actually uses. GET+POST covers
            # everything: audit records are never updated or deleted.
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "x-api-key",
                "x-audit-tenant-id",
                "x-audit-on-behalf-of",
                "x-request-id",
                "x-service-name",
            ],
            max_age=600,
        )

    app.add_middleware(
        RateLimitMiddleware,
        settings=settings,
        redis_factory=lambda: getattr(app.state, "container", None) and app.state.container.redis,
    )
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.MAX_REQUEST_BODY_BYTES)
    # The two documentation pages need different policies, because only one of
    # them is fully self-hosted. Empty when docs are disabled, which is what
    # production enforces, leaving the strict API policy everywhere.
    csp_overrides = (
        {
            "/redoc": REDOC_CSP,
            "/docs": SWAGGER_CSP,
            "/docs/oauth2-redirect": SWAGGER_CSP,
        }
        if settings.ENABLE_DOCS
        else {}
    )
    app.add_middleware(
        SecurityHeadersMiddleware,
        is_production=settings.is_production,
        csp_overrides=csp_overrides,
    )
    app.add_middleware(RequestContextMiddleware)


# Module-level app for `uvicorn app.main:app`. The CLI is the supported
# entrypoint; this exists for tooling that expects the conventional path.
app = create_app()
