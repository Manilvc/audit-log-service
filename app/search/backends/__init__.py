"""Search backends: the port, its errors, and the adapter factory.

The engine is a *deploy-time* choice, not a runtime one. One process talks to
one store, chosen by `SEARCH_BACKEND`, because the alternative - both at once -
doubles the integration matrix and buys nothing operationally: a user's trail
lives in exactly one place.
"""

from __future__ import annotations

from app.core.config import SearchEngine, Settings
from app.core.logging import get_logger
from app.search.backends.base import FieldTypes, RetentionPolicy, SearchBackend
from app.search.backends.elastic import ElasticsearchBackend
from app.search.backends.errors import (
    SearchConflict,
    SearchError,
    SearchNotFound,
    SearchRejected,
    SearchUnavailable,
)
from app.search.backends.opensearch import OpenSearchBackend

logger = get_logger(__name__)

__all__ = [
    "ElasticsearchBackend",
    "FieldTypes",
    "OpenSearchBackend",
    "RetentionPolicy",
    "SearchBackend",
    "SearchConflict",
    "SearchError",
    "SearchNotFound",
    "SearchRejected",
    "SearchUnavailable",
    "build_backend",
]


def build_backend(settings: Settings) -> SearchBackend:
    """Construct the configured search backend.

    The client libraries are imported lazily, per branch: each pulls a
    transport stack, and a deployment running one engine should not pay the
    import cost of the other.
    """
    backend: SearchBackend
    if settings.SEARCH_BACKEND is SearchEngine.ELASTICSEARCH:
        from app.search.client import build_client

        backend = ElasticsearchBackend(build_client(settings))
    else:
        from app.search.backends.opensearch import build_client as build_opensearch_client

        backend = OpenSearchBackend(build_opensearch_client(settings))

    logger.info(
        "search_backend_selected",
        engine=backend.name,
        # Worth a line in the startup log: the field types decide the mapping,
        # and on OpenSearch the user type is `keyword` rather than
        # `constant_keyword`, which changes where isolation is enforced.
        pinned_user_uuid_type=backend.field_types.pinned_user_uuid.get("type"),
    )
    return backend
