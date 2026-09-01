"""Structured logging.

Operational logs are JSON in every deployed environment so they are queryable
in the platform's log stack, and human-readable only on a local terminal.

These are *operational* logs, not audit events. The distinction matters: audit
events are evidence and go through the durable ingest path. Nothing here is
compliance evidence, which is why it is safe for this logger to drop messages
under pressure while the audit path never may.

A redacting processor runs on every record. Secrets leak into logs by accident
far more often than through the intended data path, so the filter lives at the
sink where it cannot be bypassed by a careless call site.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from app.domain.events import REDACT_KEYS, REDACTED_PLACEHOLDER

_configured = False

#: Substrings that mark a key as sensitive even when it is not an exact match
#: in REDACT_KEYS - catches `db_password`, `jwt_secret_key`, `api_key_value`.
_SENSITIVE_SUBSTRINGS = ("password", "secret", "token", "api_key", "apikey", "private")


def _redact(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Strip credential-shaped values from a log record, recursively."""

    def scrub(value: Any, depth: int = 0) -> Any:
        # Bound the recursion: a cyclic or pathologically nested structure must
        # not turn a log call into a stack overflow.
        if depth > 6:
            return value
        if isinstance(value, dict):
            return {
                key: (REDACTED_PLACEHOLDER if _is_sensitive(str(key)) else scrub(item, depth + 1))
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [scrub(item, depth + 1) for item in value]
        return value

    return {
        key: (REDACTED_PLACEHOLDER if _is_sensitive(key) else scrub(item))
        for key, item in event_dict.items()
    }


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    if lowered in REDACT_KEYS:
        return True
    return any(marker in lowered for marker in _SENSITIVE_SUBSTRINGS)


def configure_logging(*, level: str = "INFO", json_output: bool = True) -> None:
    """Install the structlog pipeline. Idempotent."""
    global _configured
    if _configured:
        return

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        # The non-stdlib variants: the sink below is PrintLoggerFactory, which
        # is faster than routing through logging.Logger but carries no `.name`,
        # so `stdlib.add_logger_name` would raise on every call. The module name
        # is bound explicitly in get_logger() instead.
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact,
    ]
    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Route uvicorn/elasticsearch stdlib loggers through the same sink so
    # output stays parseable as one stream.
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    for noisy in ("uvicorn.access", "elastic_transport.transport", "botocore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True


def get_logger(name: str) -> Any:
    """Bound logger for a module.

    The name is bound as a field rather than passed to the factory: with a
    non-stdlib logger factory the positional argument is discarded, so binding
    is the only way the module actually shows up in the output.
    """
    return structlog.get_logger().bind(logger=name)
