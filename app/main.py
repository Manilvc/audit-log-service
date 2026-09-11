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
from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
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

#: Documentation routes. Declared here because three places must agree on them:
#: the route itself, the CSP override that lets its assets load, and the link
#: between the two pages.
DOCS_PATH: Final[str] = "/docs"
REDOC_PATH: Final[str] = "/redoc"

#: Swagger UI options. `persistAuthorization` is deliberately absent: a valid
#: key here carries every scope including erase, and keeping it in the browser's
#: local storage after the tab closes is not a convenience worth that.
_SWAGGER_UI_PARAMETERS: Final[dict[str, Any]] = {
    "docExpansion": "list",
    "defaultModelsExpandDepth": 0,
    "displayRequestDuration": True,
    "filter": True,
    "tryItOutEnabled": True,
}

# Raw string: the shell examples end lines with a backslash continuation, and
# in a normal literal Python reads backslash-newline as a line join and eats
# the newline - collapsing every curl example onto one unreadable line.
_DESCRIPTION = r"""
Tamper-evident, multi-user audit log service for the EveryCRED DCS platform.

Every security-relevant action across the platform - credential issuance,
revocation, login, permission change, consent withdrawal, configuration edit -
lands here as one canonical event, in one queryable place, with cryptographic
proof it has not been altered.

**Storage** - Elasticsearch 9.x data streams, hybrid user isolation (a shared
stream by default, dedicated streams for high-volume users), with a durable
Redis Streams buffer in front and an immutable S3 Object Lock archive behind.

**Tamper evidence** - every event carries a SHA-256 hash chained to its
predecessor within its user's chain, and chain heads are periodically
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
  -H "x-audit-user-uuid: $USER_UUID" \
  -H "content-type: application/json" \
  -d '{"events":[{"action":"user.login","outcome":"success",
        "actor":{"type":"user","id":"u_123"},
        "service_name":"everycred-backend",
        "event_id":"evt_login_u123_20260831T091422Z"}]}'

# 2. Read. Allow ~1s for the worker to drain the queue into Elasticsearch.
curl -X POST "$AUDIT_URL/v1/audit/events/search" \
  -H "x-api-key: $AUDIT_API_KEY" \
  -H "x-audit-user-uuid: $USER_UUID" \
  -H "content-type: application/json" \
  -d '{"start":"now-1h","end":"now","size":20}'
```

# Authentication

One credential: the service API key, sent as `x-api-key`. There is no user
token path - this service validates no platform JWT and runs no login of its
own, so every caller is an internal service that has already enforced RBAC on
the user's behalf.

| | Service API key |
|---|---|
| Header | `x-api-key` |
| For | emitting services, machine readers |
| User | **you must send** `x-audit-user-uuid` |
| Scopes | all of them (see below) |

A valid key carries every scope: `audit:read`, `audit:write`, `audit:export`,
`audit:erase`, `audit:verify`, `audit:admin`, `audit:cross_user`. The key is
therefore a high-value secret - it is enough to crypto-shred a data subject's
personal data or read across every user - so keep it distinct per environment
and rotate it on a schedule.

A key is not bound to a user, so `x-audit-user-uuid` is what tells the service
which user the call acts for, and it is required on every user-scoped route.
On ingest, an event whose body `user_uuid` disagrees with that header is rejected
rather than silently resolved.

Three more headers are recorded rather than checked, and each is stamped onto
every event the call ingests unless the event already carries its own value:

* `x-audit-on-behalf-of` - the service user, the person the backend is acting
  for. Recorded as `actor.on_behalf_of`, so a service-mediated action is
  attributed to the human and not to the service account.
* `x-audit-issuer-id` - the issuer (sub-user), recorded as `user.issuer_id`
  and filterable on search and aggregate.
* `x-service-name` - the calling service, recorded as `actor.service`.

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

**Search, not fetch.** Reads are user-filtered searches, so an event id from
another user returns `404` rather than the record. Pagination is
cursor-based: pass the `cursor` from the previous response, and page 500 costs
what page 1 costs.

**Errors.** `400` no user named, or an identity header wider than the field it
is stored in, `401` no or unrecognised credential, `403` missing scope or another
user's data, `422` schema validation, `429` rate limited - reads are capped low
because reads are the sensitive surface, ingest is capped high because throttling
ingest means dropping evidence.
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
            dedicated_users=len(resolved.dedicated_user_set),
        )

        # Bootstrap failures are logged but do not abort startup: a replica that
        # cannot reach Elasticsearch yet must still come up and buffer writes,
        # which is the whole point of the queue. Readiness reports the problem.
        try:
            await bootstrap_cluster(container.search, resolved, container.router)
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
        # Both documentation pages are served by `_install_docs` instead. The
        # stock routes load Swagger UI and ReDoc from third-party CDNs, and an
        # audit service is exactly the kind of deployment whose browser cannot
        # reach one - the page then renders blank with no explanation.
        docs_url=None,
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


def _root_path(request: Request) -> str:
    """Prefix every asset and schema URL on a documentation page needs.

    Empty on a dedicated host; "/audit" behind the shared-domain mount, where
    nginx strips the prefix before the app sees the request. An absolute
    "/static/..." URL would then resolve against the domain root - which the
    main backend owns - and 404.
    """
    return str(request.scope.get("root_path", "")).rstrip("/")


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

    @app.get(REDOC_PATH, include_in_schema=False)
    async def redoc(request: Request) -> HTMLResponse:
        """The API reference, rendered from the schema this service publishes."""
        root = _root_path(request)
        return HTMLResponse(
            redoc_html(
                openapi_url=f"{root}{app.openapi_url or '/openapi.json'}",
                title=app.title,
                script_url=f"{root}/static/redoc.standalone.js",
                environment=settings.ENVIRONMENT.value,
                swagger_url=f"{root}{DOCS_PATH}",
            )
        )

    @app.get(DOCS_PATH, include_in_schema=False)
    async def swagger_ui(request: Request) -> HTMLResponse:
        """The interactive console, built only from assets this origin serves.

        FastAPI's own `/docs` hardcodes jsDelivr for the bundle and
        fastapi.tiangolo.com for the favicon, with no setting to redirect them,
        so the route is rebuilt here against the vendored copies in
        `app/static`. The version is pinned in `static/swagger-ui.version`.
        """
        root = _root_path(request)
        return get_swagger_ui_html(
            openapi_url=f"{root}{app.openapi_url or '/openapi.json'}",
            title=f"{app.title} - Console",
            swagger_js_url=f"{root}/static/swagger-ui-bundle.js",
            swagger_css_url=f"{root}/static/swagger-ui.css",
            swagger_favicon_url=f"{root}/static/favicon.svg",
            swagger_ui_parameters=_SWAGGER_UI_PARAMETERS,
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
                "x-audit-user-uuid",
                "x-audit-issuer-id",
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
            REDOC_PATH: REDOC_CSP,
            DOCS_PATH: SWAGGER_CSP,
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
