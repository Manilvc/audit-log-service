"""Application errors and global exception handlers.

The guiding rule is that a client learns *what to fix*, never *how the service
is built*. Stack traces, Elasticsearch error bodies, index names and query DSL
all stay server-side: on a service holding every user's audit trail, an error
message is a reconnaissance channel. The full detail goes to the structured log,
correlated by request id, so an operator can still diagnose it.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger
from app.core.responses import ORJSONResponse, envelope
from app.core.security.auth import AuthenticationError, AuthorizationError
from app.core.security.crypto import KeyRingError
from app.search.backends import SearchError, SearchRejected, SearchUnavailable
from app.search.query import QueryValidationError
from app.search.routing import InvalidUserUuidError

logger = get_logger(__name__)


class AuditServiceError(Exception):
    """Base class for errors this service raises deliberately."""

    status_code: int = status.HTTP_400_BAD_REQUEST
    message: str = "Request could not be processed."

    def __init__(self, message: str | None = None, *, data: Any = None) -> None:
        super().__init__(message or self.message)
        self.detail = message or self.message
        self.data = data


class IngestRejected(AuditServiceError):
    """An audit event or batch failed validation / user resolution."""

    # Numeric literal rather than the starlette constant: 422's constant was
    # renamed (ENTITY -> CONTENT) across versions, and the number never changes.
    status_code = 422
    message = "Audit event rejected."


class InvalidHeader(AuditServiceError):
    """An identity header is present but unusable.

    400 rather than a silent truncation: these values become the attribution on
    an immutable record, and a half-written actor id is worse than a rejected
    request the caller can fix.
    """

    status_code = status.HTTP_400_BAD_REQUEST
    message = "A request header is malformed."


class RateLimited(AuditServiceError):
    """Caller exceeded the configured per-principal rate ceiling."""

    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    message = "Rate limit exceeded."


class NotFound(AuditServiceError):
    """Requested resource is missing or not visible under the caller's scope."""

    status_code = status.HTTP_404_NOT_FOUND
    message = "Not found."


class ServiceUnavailable(AuditServiceError):
    """A required dependency (Redis, ES, archive) cannot serve this request."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    message = "A dependency is unavailable."


def _respond(status_code: int, message: str, data: Any = None) -> ORJSONResponse:
    """Build a platform-envelope error response without leaking internals."""
    return ORJSONResponse(
        content=envelope(status="fail", data=data, message=message),
        status_code=status_code,
    )


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def register_exception_handlers(app: FastAPI) -> None:
    """Install handlers for every error shape this service can produce."""

    @app.exception_handler(AuthenticationError)
    async def _auth_error(request: Request, exc: AuthenticationError) -> ORJSONResponse:
        logger.warning(
            "authentication_failed",
            path=request.url.path,
            request_id=_request_id(request),
            reason=str(exc),
        )
        # No WWW-Authenticate header: the credential is a custom header rather
        # than an HTTP authentication scheme, and advertising `Bearer` here
        # would tell a client to retry with a token this service cannot accept.
        return _respond(status.HTTP_401_UNAUTHORIZED, "Authentication required.")

    @app.exception_handler(AuthorizationError)
    async def _authz_error(request: Request, exc: AuthorizationError) -> ORJSONResponse:
        # The missing scope IS returned: the caller is already authenticated,
        # and knowing which grant they lack is what lets them request it.
        logger.warning(
            "authorization_denied",
            path=request.url.path,
            request_id=_request_id(request),
            reason=str(exc),
        )
        return _respond(status.HTTP_403_FORBIDDEN, f"Access denied: {exc}")

    @app.exception_handler(QueryValidationError)
    async def _query_error(request: Request, exc: QueryValidationError) -> ORJSONResponse:
        # Safe to surface: these messages are about the caller's own filter and
        # reveal nothing about the cluster.
        return _respond(status.HTTP_400_BAD_REQUEST, str(exc))

    @app.exception_handler(InvalidUserUuidError)
    async def _user_error(request: Request, exc: InvalidUserUuidError) -> ORJSONResponse:
        return _respond(status.HTTP_400_BAD_REQUEST, str(exc))

    @app.exception_handler(AuditServiceError)
    async def _service_error(request: Request, exc: AuditServiceError) -> ORJSONResponse:
        return _respond(exc.status_code, exc.detail, exc.data)

    @app.exception_handler(KeyRingError)
    async def _keyring_error(request: Request, exc: KeyRingError) -> ORJSONResponse:
        logger.error("keyring_failure", request_id=_request_id(request), error=str(exc))
        return _respond(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Encryption key store is unavailable. The request was not recorded.",
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> ORJSONResponse:
        # Mirrors the main backend's validation shape (field / message / type)
        # so existing clients render these errors unchanged.
        errors = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())[1:]),
                "message": error.get("msg", "invalid value"),
                "type": error.get("type", "value_error"),
            }
            for error in exc.errors()
        ]
        return ORJSONResponse(
            content={
                "status": "fail",
                "message": "Validation failed.",
                "errors": errors,
            },
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> ORJSONResponse:
        return _respond(exc.status_code, str(exc.detail))

    # The three search-store handlers are registered on the port's errors, not
    # on a client library's, so they hold whichever engine is configured. The
    # adapter in `app.search.backends` does the translation.
    @app.exception_handler(SearchRejected)
    async def _store_rejected(request: Request, exc: SearchRejected) -> ORJSONResponse:
        # Never echoed: a store error body carries index names, mappings and
        # sometimes document content from another user.
        logger.error(
            "search_store_rejected",
            request_id=_request_id(request),
            error=str(exc),
        )
        return _respond(
            status.HTTP_502_BAD_GATEWAY,
            "The audit store rejected this request. It has been logged for investigation.",
        )

    @app.exception_handler(SearchUnavailable)
    async def _store_unavailable(request: Request, exc: SearchUnavailable) -> ORJSONResponse:
        logger.error(
            "search_store_unreachable",
            request_id=_request_id(request),
            error=str(exc),
        )
        return _respond(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The audit store is temporarily unavailable.",
        )

    @app.exception_handler(SearchError)
    async def _store_error(request: Request, exc: SearchError) -> ORJSONResponse:
        # A `SearchNotFound` or `SearchConflict` reaching here is a bug - both
        # are meant to be handled where the decision belongs - so it is logged
        # as one rather than translated into a plausible-looking answer.
        logger.error(
            "search_store_error_unhandled",
            request_id=_request_id(request),
            error_type=type(exc).__name__,
            error=str(exc),
        )
        return _respond(
            status.HTTP_502_BAD_GATEWAY,
            "The audit store could not complete this request.",
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> ORJSONResponse:
        # `logger.exception` keeps the traceback server-side where it belongs.
        logger.exception(
            "unhandled_exception",
            path=request.url.path,
            request_id=_request_id(request),
        )
        request_id = _request_id(request)
        suffix = f" Reference: {request_id}." if request_id else ""
        return _respond(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"An internal error occurred.{suffix}",
        )
