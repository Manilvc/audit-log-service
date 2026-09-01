"""HTTP middleware stack.

Order is significant and runs outermost-first on the way in:

1. `RequestContextMiddleware` - assigns a request id before anything can log.
2. `SecurityHeadersMiddleware` - so headers are present even on an error response.
3. `BodyLimitMiddleware` - rejects an oversized body before it is buffered.
4. `RateLimitMiddleware` - throttles before any Elasticsearch work is done.

Rate limiting sits inside authentication (which is a dependency, not
middleware), because the limit is per principal and the principal is not known
until the token is validated. The body limit deliberately sits outside it: a
10 GB upload must be refused before it is read, whoever sends it.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable, Mapping

import structlog
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import Settings
from app.core.logging import get_logger
from app.core.responses import ORJSONResponse, envelope

logger = get_logger(__name__)

NextCall = Callable[[Request], Awaitable[Response]]

REQUEST_ID_HEADER = "x-request-id"
TRACE_ID_HEADER = "x-trace-id"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id and binds it to the logging context.

    An inbound `x-request-id` is honoured so a trace spans the whole platform,
    but it is length-capped and sanitised: it is attacker-controlled and ends up
    in log lines, where an unbounded value invites log injection.
    """

    async def dispatch(self, request: Request, call_next: NextCall) -> Response:
        inbound = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = _sanitise_id(inbound) or uuid.uuid4().hex
        trace_id = _sanitise_id(request.headers.get(TRACE_ID_HEADER, "")) or request_id

        request.state.request_id = request_id
        request.state.trace_id = trace_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id, trace_id=trace_id)

        started = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            # Logged in `finally` so a request that raises is still recorded
            # with its duration - the slow failures are the interesting ones.
            duration_ms = (time.perf_counter() - started) * 1000
            request.state.duration_ms = duration_ms

        response.headers[REQUEST_ID_HEADER] = request_id
        logger.info(
            "request_completed",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round(duration_ms, 2),
        )
        return response


#: CSP for every API response. A JSON API should never load or frame anything,
#: and this still matters for JSON: a response rendered directly in a browser is
#: an XSS vector without `nosniff` alongside it.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

#: CSP for the branded ReDoc page at `/redoc`.
#:
#: Every asset it needs is served from this origin - the bundle is vendored
#: under `app/static` and the page uses the system font stack - so no external
#: origin appears here at all. What it does need:
#:
#: * `'unsafe-inline'` for script, because the `Redoc.init(...)` call is an
#:   inline <script>, and for style, because ReDoc is built on styled-components
#:   and injects its stylesheet at runtime.
#: * `blob:` workers, which ReDoc uses for search indexing.
#: * `data:` images for the icons it inlines.
REDOC_CSP = (
    "default-src 'none'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; child-src 'self' blob:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

#: CSP for Swagger UI at `/docs`.
#:
#: Unlike ReDoc this one is still FastAPI's stock page, which loads its bundle
#: and stylesheet from jsDelivr, so that origin has to be allowed for the page
#: to render at all - under `default-src 'none'` it returns 200 and then draws
#: nothing, with the reason visible only in the browser console.
#:
#: It is the interactive console rather than the reference, so the looser policy
#: buys "try it out" against a live server. Vendoring `swagger-ui-dist` the way
#: ReDoc is vendored would let this collapse into REDOC_CSP.
SWAGGER_CSP = (
    "default-src 'none'; "
    "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "font-src 'self' https://cdn.jsdelivr.net data:; "
    "img-src 'self' https://fastapi.tiangolo.com data:; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defensive response headers.

    Every response gets `API_CSP`. A path listed in `csp_overrides` gets its own
    policy instead, which is how the documentation pages are served: the strict
    API policy blocks the assets they are built from.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        is_production: bool,
        csp_overrides: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(app)
        self._is_production = is_production
        # Empty when docs are disabled, so the strict policy then applies
        # everywhere with no path ever taking a relaxed branch.
        self._csp_overrides: Mapping[str, str] = csp_overrides or {}

    async def dispatch(self, request: Request, call_next: NextCall) -> Response:
        response = await call_next(request)
        # Exact path match, not a prefix test: `startswith("/docs")` would also
        # relax a route like `/docs-export` if one were ever added.
        csp = self._csp_overrides.get(request.url.path, API_CSP)
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        # Audit responses contain personal data; no cache may retain them.
        response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
        response.headers.setdefault("Pragma", "no-cache")
        if self._is_production:
            # Only sent in production: on a local HTTP origin, HSTS would pin
            # the browser to https://localhost and break development.
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        # Suppress the server banner - free version disclosure otherwise.
        response.headers["Server"] = "audit"
        return response


class BodyLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized request bodies.

    Checks `Content-Length` first, which refuses the request before a byte of
    body is read. A chunked request without the header is still bounded by the
    per-batch size limit in the ingest schema, so this is defence in depth
    rather than the only control.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        super().__init__(app)
        self._max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: NextCall) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self._max_bytes:
            logger.warning(
                "request_body_too_large",
                declared_bytes=int(declared),
                limit=self._max_bytes,
                path=request.url.path,
            )
            return ORJSONResponse(
                content=envelope(
                    status="fail",
                    message=(
                        f"Request body exceeds the {self._max_bytes} byte limit. "
                        "Split the batch into smaller requests."
                    ),
                ),
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Fixed-window rate limit, keyed per caller.

    Backed by Redis so the limit is cluster-wide: an in-process counter would let
    N replicas allow N times the configured rate. `INCR` + `EXPIRE` in a
    pipeline is atomic enough for a fixed window and far cheaper than a sliding
    log, and the trade-off - up to 2x the limit across a window boundary - is
    irrelevant for an abuse control.

    A Redis outage *allows* the request. Blocking writes would mean losing audit
    evidence to protect against a load problem, which is the wrong way round;
    the failure is logged loudly instead.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings,
        redis_factory: Callable[[], object] | None = None,
    ) -> None:
        super().__init__(app)
        self._settings = settings
        self._redis_factory = redis_factory

    async def dispatch(self, request: Request, call_next: NextCall) -> Response:
        if not self._settings.RATE_LIMIT_ENABLED or self._redis_factory is None:
            return await call_next(request)
        if request.url.path.endswith(("/health", "/health/live", "/health/ready", "/metrics")):
            return await call_next(request)

        redis = self._redis_factory()
        if redis is None:
            return await call_next(request)

        is_ingest = "/events" in request.url.path and request.method == "POST"
        limit = (
            self._settings.INGEST_RATE_LIMIT_PER_MINUTE
            if is_ingest
            else self._settings.READ_RATE_LIMIT_PER_MINUTE
        )
        identity = _rate_limit_identity(request)
        window = int(time.time() // 60)
        key = f"audit:rl:{identity}:{window}"

        try:
            pipe = redis.pipeline(transaction=False)  # type: ignore[attr-defined]
            pipe.incr(key)
            pipe.expire(key, 120)
            count = int((await pipe.execute())[0])
        except Exception as exc:
            logger.error("rate_limit_backend_unavailable", error=str(exc))
            return await call_next(request)

        if count > limit:
            retry_after = 60 - int(time.time() % 60)
            logger.warning("rate_limited", identity=identity, count=count, limit=limit)
            return ORJSONResponse(
                content=envelope(
                    status="fail",
                    message=f"Rate limit of {limit} requests/minute exceeded.",
                ),
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count))
        return response


def _rate_limit_identity(request: Request) -> str:
    """Derive a stable, non-secret rate-limit bucket for the caller.

    An API key is hashed rather than used directly: the key would otherwise
    appear verbatim in a Redis key, visible to anyone with `MONITOR` or a
    keyspace dump.
    """
    api_key = request.headers.get("x-api-key")
    if api_key:
        import hashlib

        return "svc:" + hashlib.sha256(api_key.encode()).hexdigest()[:16]

    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        import hashlib

        return "usr:" + hashlib.sha256(auth[7:].encode()).hexdigest()[:16]

    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


def _sanitise_id(value: str) -> str:
    """Keep only characters safe to place in a log line and a header."""
    cleaned = "".join(char for char in value if char.isalnum() or char in "-_")
    return cleaned[:64]
