"""The search port, and the Elasticsearch adapter behind it.

These tests are the equivalence guard for the OpenSearch work. The port was
extracted from working code, so the thing worth proving is that nothing moved:
the index topology this service applies to a cluster - field types, lifecycle
attachment, ILM phases - must be byte-for-byte what it was before the adapter
existed. If any of it drifts, a deploy silently changes the mapping of a data
stream holding six years of audit evidence.

They also pin the two behaviours the second adapter has to reproduce: the
translation from client exceptions to the port's errors, and the refusal to
start when the configured engine has no adapter.
"""

from __future__ import annotations

from typing import Any

import pytest
from elasticsearch import (
    ApiError,
    BadRequestError,
    ConflictError,
    NotFoundError,
    TransportError,
)

from app.core.config import SearchEngine, Settings
from app.search.backends import (
    ElasticsearchBackend,
    RetentionPolicy,
    SearchBackend,
    SearchConflict,
    SearchNotFound,
    SearchRejected,
    SearchUnavailable,
    build_backend,
)
from app.search.backends.elastic import ELASTIC_FIELD_TYPES, _translated, ilm_policy
from app.search.mappings import dedicated_index_template, shared_index_template
from app.search.routing import TenantRouter

RETENTION = RetentionPolicy(
    retention_days=2190,
    rollover_max_primary_shard_size="50gb",
    rollover_max_age="30d",
)


class _Meta:
    """Stand-in for `elastic_transport.ApiResponseMeta`.

    The real one needs a node config and response headers; `str(exc)` only
    reads the status, and the status is all these tests care about.
    """

    status = 404


def _api_error(kind: type[ApiError], message: str) -> ApiError:
    """Build a client exception the way the client would raise it."""
    return kind(message, _Meta(), None)  # type: ignore[arg-type]


@pytest.fixture
def backend() -> ElasticsearchBackend:
    """The adapter with no client behind it.

    Every assertion here is about what the adapter *renders* - types, settings,
    policy documents - none of which touches the network.
    """
    return ElasticsearchBackend(client=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The port contract
# ---------------------------------------------------------------------------
def test_the_elasticsearch_adapter_satisfies_the_port(backend: ElasticsearchBackend) -> None:
    """Structural, not nominal: a second adapter needs no base class."""
    assert isinstance(backend, SearchBackend)
    assert backend.name == "elasticsearch"


def test_configuring_elasticsearch_builds_the_elastic_adapter() -> None:
    """The engine is resolved once, at startup, from one setting.

    The OpenSearch half of this lives in `test_opensearch_backend.py`; what
    matters here is that the default stays Elasticsearch, so an existing
    deployment that sets nothing keeps the store it already has.
    """
    settings = Settings(SEARCH_BACKEND=SearchEngine.ELASTICSEARCH)
    assert settings.SEARCH_BACKEND is SearchEngine.ELASTICSEARCH
    assert Settings().SEARCH_BACKEND is SearchEngine.ELASTICSEARCH
    assert isinstance(build_backend(settings), ElasticsearchBackend)


# ---------------------------------------------------------------------------
# Field types: the mapping must not move
# ---------------------------------------------------------------------------
def test_elastic_field_types_are_the_elastic_ones(backend: ElasticsearchBackend) -> None:
    """The three types with no cross-engine equivalent, pinned by value."""
    types = backend.field_types
    assert types is ELASTIC_FIELD_TYPES
    assert types.subtree == {"type": "flattened"}
    assert types.log_text == {"type": "match_only_text"}
    assert types.pinned_tenant == {"type": "constant_keyword"}


def test_lifecycle_attaches_through_the_index_settings(backend: ElasticsearchBackend) -> None:
    assert backend.lifecycle_index_settings("audit-retention") == {
        "lifecycle": {"name": "audit-retention"}
    }


def _properties(template: dict[str, Any]) -> dict[str, Any]:
    return dict(template["template"]["mappings"]["properties"])


def test_shared_template_is_unchanged_by_the_port(backend: ElasticsearchBackend) -> None:
    """Exactly the mapping the service applied before the adapter existed."""
    template = shared_index_template(
        name_pattern="audit-shared",
        shards=3,
        replicas=1,
        backend=backend,
        policy_name="audit-retention",
    )
    properties = _properties(template)

    assert properties["tenant"]["properties"]["id"] == {"type": "keyword"}
    assert properties["labels"] == {"type": "flattened"}
    assert properties["message"] == {"type": "match_only_text"}
    assert properties["change"]["properties"]["before"] == {"type": "flattened"}
    assert properties["change"]["properties"]["after"] == {"type": "flattened"}

    settings = template["template"]["settings"]["index"]
    assert settings["lifecycle"] == {"name": "audit-retention"}
    assert settings["number_of_shards"] == 3
    # Custom routing pins a shared tenant to one shard; it must stay on.
    assert template["data_stream"] == {"allow_custom_routing": True}


def test_dedicated_template_still_pins_the_tenant_id(backend: ElasticsearchBackend) -> None:
    """`constant_keyword` is a tenant-isolation control, not a size tweak.

    On a dedicated stream the engine itself rejects a document carrying another
    tenant's id. `docs/SECURITY.md` counts that as a layer, so it has to survive
    the refactor - and its absence on another engine is a decision, not an
    accident.
    """
    template = dedicated_index_template(
        name_pattern="audit-t-*",
        shards=1,
        replicas=1,
        backend=backend,
        policy_name="audit-retention",
    )
    properties = _properties(template)

    assert properties["tenant"]["properties"]["id"] == {"type": "constant_keyword"}
    # No custom routing here: a dedicated stream has no routing key to supply,
    # and enabling it would reject every write with routing_missing_exception.
    assert template["data_stream"] == {}


def test_dedicated_template_outranks_the_shared_one(backend: ElasticsearchBackend) -> None:
    """Otherwise `audit-t-<uuid>-*` could match the broader shared pattern."""
    shared = shared_index_template(
        name_pattern=TenantRouter(
            shared_stream="audit-shared", index_prefix="audit", dedicated_tenants=frozenset()
        ).shared_pattern(),
        shards=3,
        replicas=1,
        backend=backend,
        policy_name="p",
    )
    dedicated = dedicated_index_template(
        name_pattern="audit-t-*", shards=1, replicas=1, backend=backend, policy_name="p"
    )
    assert dedicated["priority"] > shared["priority"]


# ---------------------------------------------------------------------------
# ILM policy
# ---------------------------------------------------------------------------
def test_ilm_policy_keeps_its_four_phases() -> None:
    policy = ilm_policy(RETENTION)
    assert list(policy["phases"]) == ["hot", "warm", "cold", "delete"]
    assert policy["phases"]["hot"]["actions"]["rollover"] == {
        "max_primary_shard_size": "50gb",
        "max_age": "30d",
    }
    # Read-only and single-segment in warm; replicas dropped in cold, where
    # durability comes from the WORM archive rather than a second copy.
    assert policy["phases"]["warm"]["actions"]["forcemerge"] == {"max_num_segments": 1}
    assert policy["phases"]["cold"]["actions"]["allocate"] == {"number_of_replicas": 0}


def test_delete_phase_is_the_retention_ceiling() -> None:
    """Six years by default - the HIPAA 164.316(b)(2)(i) floor.

    Deleting earlier would break the hash chain, which is why erasure is served
    by crypto-shredding instead.
    """
    assert ilm_policy(RETENTION)["phases"]["delete"]["min_age"] == "2190d"


# ---------------------------------------------------------------------------
# Error translation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (_api_error(NotFoundError, "missing"), SearchNotFound),
        (_api_error(ConflictError, "version conflict"), SearchConflict),
        (_api_error(BadRequestError, "illegal_argument_exception"), SearchRejected),
        (_api_error(ApiError, "unavailable_shards"), SearchRejected),
        (TransportError("connection refused"), SearchUnavailable),
    ],
)
def test_client_exceptions_become_port_errors(raised: Exception, expected: type) -> None:
    """Nothing above the adapter imports an engine's exception classes."""
    with pytest.raises(expected), _translated():
        raise raised


def test_already_exists_is_a_conflict_despite_its_400() -> None:
    """Elasticsearch reports a lost create race as 400, not 409.

    Callers treat a conflict as success - another replica got there first - so
    misclassifying it as a rejection would fail a bootstrap that in fact worked.
    """
    with pytest.raises(SearchConflict), _translated():
        raise _api_error(BadRequestError, "resource_already_exists_exception: taken")
