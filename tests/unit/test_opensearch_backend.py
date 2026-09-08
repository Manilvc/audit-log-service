"""The OpenSearch adapter, and the write guard that replaces what it cannot do.

Nothing here needs a cluster: every assertion is about what the adapter
*renders* or how it *classifies*, which is where the two engines actually
diverge. The integration suite covers the rest against a live OpenSearch.

The most important test in this file is the last one. On Elasticsearch, a
dedicated stream's `constant_keyword` makes the engine itself refuse a document
carrying another tenant's id - `docs/SECURITY.md` counts that as a layer of the
isolation model. OpenSearch has no dependable equivalent, so the guarantee moved
into `AuditRepository.bulk_index`, where it holds on both engines and on the
shared stream too. That is the one place a regression would silently weaken
tenant isolation.
"""

from __future__ import annotations

from typing import Any

import pytest
from opensearchpy.exceptions import (
    AuthorizationException,
    ConflictError,
    NotFoundError,
    RequestError,
    TransportError,
)
from opensearchpy.exceptions import (
    ConnectionError as OpenSearchConnectionError,
)

from app.core.config import SearchEngine, Settings
from app.search.backends import (
    OpenSearchBackend,
    RetentionPolicy,
    SearchBackend,
    SearchConflict,
    SearchNotFound,
    SearchRejected,
    SearchUnavailable,
    build_backend,
)
from app.search.backends.opensearch import (
    OPENSEARCH_FIELD_TYPES,
    _translated,
    ism_policy,
)
from app.search.mappings import dedicated_index_template, shared_index_template
from app.search.query import AuditSearchFilter, TenantScope, build_search_body
from app.search.repository import AuditRepository
from app.search.routing import TenantRouter

RETENTION = RetentionPolicy(
    retention_days=2190,
    rollover_max_primary_shard_size="50gb",
    rollover_max_age="30d",
)
PATTERNS = ("audit-shared", "audit-t-*")


@pytest.fixture
def backend() -> OpenSearchBackend:
    """The adapter with no client behind it - nothing here touches the network."""
    return OpenSearchBackend(client=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# The port contract
# ---------------------------------------------------------------------------
def test_the_opensearch_adapter_satisfies_the_port(backend: OpenSearchBackend) -> None:
    assert isinstance(backend, SearchBackend)
    assert backend.name == "opensearch"


def test_configuring_opensearch_builds_the_opensearch_adapter() -> None:
    """The engine is a deploy-time choice, resolved once at startup."""
    settings = Settings(
        SEARCH_BACKEND=SearchEngine.OPENSEARCH,
        ES_HOSTS=["https://search-example.ap-south-1.es.amazonaws.com"],
        ES_USERNAME="audit_admin",
        ES_PASSWORD="not-a-real-password",
    )
    resolved = build_backend(settings)
    assert isinstance(resolved, OpenSearchBackend)
    assert resolved.name == "opensearch"


#: Explicit "no credential at all". Clearing the process environment is not
#: enough - `conftest` exports test credentials and `Settings` also reads
#: `.env`, so the absence has to be stated rather than arranged.
_NO_CREDENTIALS: dict[str, Any] = {
    "ES_USERNAME": None,
    "ES_PASSWORD": None,
    "ES_API_KEY": None,
}


def test_sigv4_needs_no_stored_credential() -> None:
    """The Elasticsearch credential rule would reject a correct AWS domain.

    SigV4 signs with the instance role, so there is no username or password in
    the settings at all - and demanding one would make the safer configuration
    the unstartable one.
    """
    settings = Settings(
        SEARCH_BACKEND=SearchEngine.OPENSEARCH,
        ES_HOSTS=["https://search-example.ap-south-1.es.amazonaws.com"],
        OPENSEARCH_AWS_SIGV4=True,
        **_NO_CREDENTIALS,
    )
    assert settings.OPENSEARCH_AWS_SIGV4 is True


def test_opensearch_without_any_credential_is_refused() -> None:
    """Startup fails loudly rather than reaching an unauthenticated store."""
    with pytest.raises(ValueError, match="OpenSearch credentials missing"):
        Settings(
            SEARCH_BACKEND=SearchEngine.OPENSEARCH,
            ES_HOSTS=["https://search-example.ap-south-1.es.amazonaws.com"],
            **_NO_CREDENTIALS,
        )


# ---------------------------------------------------------------------------
# Field types
# ---------------------------------------------------------------------------
def test_opensearch_field_types(backend: OpenSearchBackend) -> None:
    """`flat_object` and `text` substitute; `keyword` is a decision.

    `constant_keyword` availability varies across 2.x minors, so relying on it
    would make a security control depend on a patch version.
    """
    types = backend.field_types
    assert types is OPENSEARCH_FIELD_TYPES
    assert types.subtree == {"type": "flat_object"}
    assert types.log_text == {"type": "text"}
    assert types.pinned_tenant == {"type": "keyword"}


def test_ism_needs_no_index_setting(backend: OpenSearchBackend) -> None:
    """ISM claims indices from inside the policy, not from the template."""
    assert backend.lifecycle_index_settings("audit-retention") == {}


def test_templates_render_with_opensearch_types(backend: OpenSearchBackend) -> None:
    shared = shared_index_template(
        name_pattern="audit-shared",
        shards=3,
        replicas=1,
        backend=backend,
        policy_name="audit-retention",
    )
    properties = shared["template"]["mappings"]["properties"]
    assert properties["labels"] == {"type": "flat_object"}
    assert properties["message"] == {"type": "text"}
    # No ILM setting leaks into an OpenSearch template.
    assert "lifecycle" not in shared["template"]["settings"]["index"]

    dedicated = dedicated_index_template(
        name_pattern="audit-t-*",
        shards=1,
        replicas=1,
        backend=backend,
        policy_name="audit-retention",
    )
    tenant_id = dedicated["template"]["mappings"]["properties"]["tenant"]["properties"]["id"]
    assert tenant_id == {"type": "keyword"}


# ---------------------------------------------------------------------------
# ISM policy
# ---------------------------------------------------------------------------
def test_ism_policy_mirrors_the_ilm_phases() -> None:
    """Same intent as ILM, in ISM's vocabulary."""
    policy = ism_policy(RETENTION, index_patterns=PATTERNS)["policy"]

    assert policy["default_state"] == "hot"
    assert [state["name"] for state in policy["states"]] == ["hot", "warm", "cold", "delete"]

    actions = {
        state["name"]: [key for action in state["actions"] for key in action]
        for state in policy["states"]
    }
    assert "rollover" in actions["hot"]
    # ILM's `forcemerge`/`readonly`/`allocate`/`set_priority` are renamed.
    assert "force_merge" in actions["warm"]
    assert "read_only" in actions["warm"]
    assert "replica_count" in actions["cold"]
    assert actions["delete"] == ["delete"]


def test_ism_transitions_carry_the_retention_ceiling() -> None:
    policy = ism_policy(RETENTION, index_patterns=PATTERNS)["policy"]
    transitions = {state["name"]: state["transitions"] for state in policy["states"]}
    assert transitions["hot"][0]["conditions"]["min_index_age"] == "30d"
    assert transitions["warm"][0]["conditions"]["min_index_age"] == "180d"
    # Six years, the HIPAA 164.316(b)(2)(i) floor.
    assert transitions["cold"][0]["conditions"]["min_index_age"] == "2190d"
    # Nothing after delete.
    assert transitions["delete"] == []


def test_ism_template_claims_both_audit_patterns() -> None:
    """Otherwise a rolled-over backing index would age out of the policy."""
    policy = ism_policy(RETENTION, index_patterns=PATTERNS)["policy"]
    assert policy["ism_template"][0]["index_patterns"] == list(PATTERNS)
    assert policy["ism_template"][0]["priority"] > 0


def test_rollover_uses_ism_condition_names() -> None:
    """`min_primary_shard_size`/`min_index_age`, not ILM's `max_*`."""
    policy = ism_policy(RETENTION, index_patterns=PATTERNS)["policy"]
    rollover = next(
        action["rollover"] for action in policy["states"][0]["actions"] if "rollover" in action
    )
    assert rollover == {"min_primary_shard_size": "50gb", "min_index_age": "30d"}


# ---------------------------------------------------------------------------
# Error translation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (NotFoundError(404, "index_not_found_exception"), SearchNotFound),
        (ConflictError(409, "version_conflict_engine_exception"), SearchConflict),
        (RequestError(400, "illegal_argument_exception"), SearchRejected),
        (AuthorizationException(403, "security_exception"), SearchRejected),
        (OpenSearchConnectionError("N/A", "connection refused", "info"), SearchUnavailable),
        # A transport error with no status never reached the cluster: retryable.
        (TransportError("N/A", "read timeout"), SearchUnavailable),
        # One with a status did reach it and was refused.
        (TransportError(503, "unavailable_shards_exception"), SearchRejected),
    ],
)
def test_client_exceptions_become_port_errors(raised: Exception, expected: type) -> None:
    """Every OpenSearch error derives from TransportError, so order matters."""
    with pytest.raises(expected), _translated():
        raise raised


def test_already_exists_is_a_conflict(backend: OpenSearchBackend) -> None:
    """Same 400-not-409 quirk as Elasticsearch; callers treat it as success."""
    with pytest.raises(SearchConflict), _translated():
        raise RequestError(400, "resource_already_exists_exception")


# ---------------------------------------------------------------------------
# The write guard: what replaces constant_keyword, on every engine
# ---------------------------------------------------------------------------
class _RecordingStore:
    """Captures the bulk body instead of sending it."""

    def __init__(self) -> None:
        self.calls: list[list[dict[str, Any]]] = []

    async def bulk(
        self,
        operations: list[dict[str, Any]],
        *,
        refresh: bool | str = False,
    ) -> dict[str, Any]:
        self.calls.append(operations)
        return {"took": 1, "errors": False}


@pytest.fixture
def store() -> _RecordingStore:
    return _RecordingStore()


@pytest.fixture
def repository(store: _RecordingStore, router: TenantRouter) -> AuditRepository:
    return AuditRepository(
        store,  # type: ignore[arg-type]
        router,
        max_window_days=90,
        search_timeout="10s",
    )


def _document(tenant_id: str, event_id: str = "evt-1") -> dict[str, Any]:
    return {"event": {"id": event_id}, "tenant": {"id": tenant_id}}


async def test_a_document_bound_for_the_wrong_tenant_is_never_written(
    repository: AuditRepository, store: _RecordingStore, router: TenantRouter
) -> None:
    """The invariant the whole isolation model rests on.

    Elasticsearch enforces this itself on a dedicated stream. OpenSearch does
    not, and neither engine does on the shared stream - so it is enforced here,
    before the write, on every engine and every stream.
    """
    route = router.resolve("tenant-a")
    outcome = await repository.bulk_index([(route, _document("tenant-b"))])

    assert store.calls == [], "a foreign-tenant document reached the store"
    assert outcome.succeeded == 0
    assert len(outcome.failed) == 1
    assert "tenant_mismatch" in outcome.failed[0][1]


async def test_a_document_with_no_tenant_is_never_written(
    repository: AuditRepository, store: _RecordingStore, router: TenantRouter
) -> None:
    route = router.resolve("tenant-a")
    outcome = await repository.bulk_index([(route, {"event": {"id": "evt-1"}})])

    assert store.calls == []
    assert "carries no tenant.id" in outcome.failed[0][1]


async def test_the_mismatch_reason_is_classified_as_permanent(
    repository: AuditRepository, router: TenantRouter
) -> None:
    """It must dead-letter, not retry.

    A routing bug fails identically forever; retrying it burns a chain
    reservation on every attempt and buries the alert.
    """
    from app.queue.worker import _is_permanent

    route = router.resolve("tenant-a")
    outcome = await repository.bulk_index([(route, _document("tenant-b"))])
    assert _is_permanent(outcome.failed[0][1])


async def test_good_documents_still_go_through_alongside_a_rejected_one(
    repository: AuditRepository, store: _RecordingStore, router: TenantRouter
) -> None:
    """One bad document must not discard the batch.

    Partial success is the normal case: the other events are evidence, and
    dropping them to punish a routing bug loses more than it protects.
    """
    route = router.resolve("tenant-a")
    outcome = await repository.bulk_index(
        [
            (route, _document("tenant-a", "evt-good-1")),
            (route, _document("tenant-b", "evt-bad")),
            (route, _document("tenant-a", "evt-good-2")),
        ]
    )

    assert outcome.succeeded == 2
    assert len(outcome.failed) == 1
    # Two action/document pairs reached the store, and neither is the bad one.
    (sent,) = store.calls
    written_ids = [action["create"]["_id"] for action in sent[::2]]
    assert written_ids == ["evt-good-1", "evt-good-2"]


# ---------------------------------------------------------------------------
# Engine capabilities the integration run surfaced
# ---------------------------------------------------------------------------
def test_opensearch_data_streams_take_no_custom_routing(backend: OpenSearchBackend) -> None:
    """A routed write to an OpenSearch data stream is rejected outright:

        illegal_argument_exception: index request targeting data stream [...]
        specifies a custom routing.

    There is no template flag to turn it on, so the router must issue no key.
    """
    assert backend.supports_custom_routing is False


def test_router_omits_the_routing_key_when_the_engine_refuses_it() -> None:
    """The router and the template have to agree, or every shared write fails."""
    unrouted = TenantRouter(
        shared_stream="audit-shared",
        index_prefix="audit",
        dedicated_tenants=frozenset(),
        custom_routing=False,
    )
    assert unrouted.resolve("tenant-a").routing_key is None

    # The default stays Elasticsearch behaviour, where routing pins a shared
    # tenant to one shard.
    routed = TenantRouter(
        shared_stream="audit-shared", index_prefix="audit", dedicated_tenants=frozenset()
    )
    assert routed.resolve("tenant-a").routing_key == "tenant-a"


def test_shared_template_drops_the_routing_flag_for_opensearch(
    backend: OpenSearchBackend,
) -> None:
    """`allow_custom_routing` on the template would promise what the engine refuses."""
    shared = shared_index_template(
        name_pattern="audit-shared",
        shards=3,
        replicas=1,
        backend=backend,
        policy_name="p",
    )
    assert shared["data_stream"] == {}


def test_opensearch_sort_takes_no_date_format(backend: OpenSearchBackend) -> None:
    """`field_sort` has no `format` key here.

    Sending one is `x_content_parse_exception: [field_sort] unknown field
    [format]`, which fails every read rather than degrading.
    """
    assert backend.sort_date_format is None

    body = build_search_body(
        TenantScope(tenant_id="tenant-a"),
        AuditSearchFilter(),
        size=10,
        max_window_days=90,
        sort_date_format=backend.sort_date_format,
    )
    timestamp_sort = body["sort"][0]["@timestamp"]
    assert "format" not in timestamp_sort
    assert timestamp_sort["order"] == "desc"


def test_elasticsearch_keeps_the_formatted_sort_value() -> None:
    """The default, and what an Elasticsearch cursor carries."""
    body = build_search_body(
        TenantScope(tenant_id="tenant-a"),
        AuditSearchFilter(),
        size=10,
        max_window_days=90,
    )
    assert body["sort"][0]["@timestamp"]["format"] == "strict_date_optional_time"
