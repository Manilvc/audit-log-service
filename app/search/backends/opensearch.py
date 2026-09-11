"""OpenSearch adapter for the search port.

Everything that differs from Elasticsearch lives here. The query DSL, bulk
writes, `search_after` pagination and `op_type: create` idempotency are
identical, so the repository and the query builder are shared untouched. What is
not identical:

**Retention is ISM, not ILM.** OpenSearch has no `_ilm`; the Index State
Management plugin takes a states-and-transitions document at
``_plugins/_ism/policies/<name>``, and it attaches itself to indices through an
``ism_template`` matching index patterns rather than through an index setting.
That is why `lifecycle_index_settings` returns nothing here and
`ensure_lifecycle_policy` takes the patterns.

**Three field types have no equivalent.** `flattened` becomes `flat_object`,
`match_only_text` becomes plain `text`, and `constant_keyword` is deliberately
not used - see `OPENSEARCH_FIELD_TYPES` for why that one is a security decision
rather than a substitution.

**Auth is basic or SigV4.** A managed AWS domain with fine-grained access
control accepts the same username and password the Elasticsearch path uses;
`OPENSEARCH_AWS_SIGV4=true` signs requests with the instance's IAM credentials
instead, so no long-lived password sits on the audit host.

The client library is `opensearch-py`, pinned below 3.0 on purpose: 3.x pulls
`grpcio` and `protobuf` for a gRPC transport this service does not use, and an
audit store is the wrong place to add native dependencies for nothing.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any, Final

from opensearchpy import (
    AsyncHttpConnection,
    AsyncOpenSearch,
    AWSV4SignerAsyncAuth,
)
from opensearchpy.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ConflictError,
    NotFoundError,
    RequestError,
    SerializationError,
    SSLError,
    TransportError,
)
from opensearchpy.exceptions import (
    ConnectionError as OpenSearchConnectionError,
)

from app.core.config import Settings
from app.core.logging import get_logger
from app.search.backends.base import FieldTypes, RetentionPolicy
from app.search.backends.errors import (
    SearchConflict,
    SearchNotFound,
    SearchRejected,
    SearchUnavailable,
)

logger = get_logger(__name__)

#: OpenSearch equivalents for the three types Elasticsearch supplies natively.
#:
#: `pinned_user_uuid` is plain `keyword`, not `constant_keyword`, and that is a
#: decision rather than an oversight. Availability of `constant_keyword` varies
#: across OpenSearch 2.x minors, so depending on it would make the user
#: backstop a function of which patch version a domain happens to run - the
#: worst possible property for a security control. Instead the guarantee is
#: enforced in `AuditRepository.bulk_index`, which refuses to write a document
#: whose `user.uuid` disagrees with its route, on **both** engines. The engine
#: check remains a second layer where the engine offers it.
OPENSEARCH_FIELD_TYPES: Final[FieldTypes] = FieldTypes(
    subtree={"type": "flat_object"},
    log_text={"type": "text"},
    pinned_user_uuid={"type": "keyword"},
)

#: AWS signing service name. `es` covers managed domains; Serverless
#: collections use `aoss` and are not supported - they restrict the templates,
#: ISM and point-in-time APIs this service provisions with.
_SIGV4_SERVICE: Final[str] = "es"

#: Where the ISM plugin keeps its policies.
_ISM_POLICY_PATH: Final[str] = "/_plugins/_ism/policies"


@contextlib.contextmanager
def _translated() -> Iterator[None]:
    """Map client exceptions onto the port's errors.

    Unlike the Elasticsearch client, every OpenSearch error derives from
    `TransportError` - a 404 and a dead socket share a base class. So the
    specific statuses are caught first, the connection failures next, and the
    catch-all decides by whether a status code came back at all: with one, the
    server answered and rejected us; without, we never reached it.
    """
    try:
        yield
    except NotFoundError as exc:
        raise SearchNotFound(str(exc)) from exc
    except ConflictError as exc:
        raise SearchConflict(str(exc)) from exc
    except RequestError as exc:
        if "resource_already_exists_exception" in str(exc):
            raise SearchConflict(str(exc)) from exc
        raise SearchRejected(str(exc)) from exc
    except (AuthenticationException, AuthorizationException) as exc:
        # Not retryable and not the caller's request shape: a credential or a
        # fine-grained-access-control role is wrong.
        raise SearchRejected(str(exc)) from exc
    except (OpenSearchConnectionError, SSLError, SerializationError) as exc:
        raise SearchUnavailable(str(exc)) from exc
    except TransportError as exc:
        if isinstance(exc.status_code, int):
            raise SearchRejected(str(exc)) from exc
        raise SearchUnavailable(str(exc)) from exc


def build_client(settings: Settings) -> AsyncOpenSearch:
    """Construct a hardened async OpenSearch client.

    The `ES_*` settings are shared: hosts, timeouts and TLS mean the same thing
    to both engines. Only the credential differs, and the AWS endpoint is HTTPS
    on 443 rather than 9200 - which is why `ES_HOSTS` carries the scheme.
    """
    auth: dict[str, Any] = {}
    if settings.OPENSEARCH_AWS_SIGV4:
        # Imported here rather than at module scope: botocore is only needed on
        # the AWS path, and importing it costs ~100ms of startup otherwise.
        from botocore.session import get_session

        credentials = get_session().get_credentials()
        if credentials is None:
            raise RuntimeError(
                "OPENSEARCH_AWS_SIGV4 is set but no AWS credentials were found. "
                "Attach an instance role, or set AWS_ACCESS_KEY_ID and "
                "AWS_SECRET_ACCESS_KEY."
            )
        auth["http_auth"] = AWSV4SignerAsyncAuth(credentials, settings.AWS_REGION, _SIGV4_SERVICE)
    elif settings.ES_USERNAME and settings.ES_PASSWORD:
        auth["http_auth"] = (settings.ES_USERNAME, settings.ES_PASSWORD.get_secret_value())

    ssl_context = settings.es_ssl_context()
    if ssl_context is not None:
        auth["ssl_context"] = ssl_context

    return AsyncOpenSearch(
        hosts=settings.ES_HOSTS,
        # Required for the async client: the default connection class is
        # synchronous, and mixing it into the event loop blocks every request.
        connection_class=AsyncHttpConnection,
        timeout=settings.ES_REQUEST_TIMEOUT,
        max_retries=settings.ES_MAX_RETRIES,
        retry_on_timeout=True,
        verify_certs=settings.ES_VERIFY_CERTS,
        **auth,
    )


class OpenSearchBackend:
    """The search port, backed by OpenSearch."""

    def __init__(self, client: AsyncOpenSearch) -> None:
        self._client = client

    # --------------------------------------------------------------- identity
    @property
    def name(self) -> str:
        return "opensearch"

    @property
    def field_types(self) -> FieldTypes:
        return OPENSEARCH_FIELD_TYPES

    @property
    def sort_date_format(self) -> str | None:
        """None: `field_sort` has no `format` key here.

        Sending one is `x_content_parse_exception: [field_sort] unknown field
        [format]`, so the sort value comes back as epoch millis and the
        `search_after` cursor carries that instead.
        """
        return None

    @property
    def supports_custom_routing(self) -> bool:
        """No. OpenSearch data streams reject a routed write outright:

            illegal_argument_exception: index request targeting data stream
            [...] specifies a custom routing. target the backing indices
            directly or remove the custom routing.

        There is no template flag to enable it, so the shared stream is written
        unrouted here and a user's searches fan out across its shards. The
        cost is search efficiency on the shared stream; isolation is unchanged,
        because that comes from the mandatory user filter. A user whose
        volume makes the fan-out expensive is the case dedicated streams exist
        for, and those never used routing on either engine.
        """
        return False

    def lifecycle_index_settings(self, policy_name: str) -> dict[str, Any]:
        """Nothing: ISM attaches through its own `ism_template`, not a setting.

        The older `plugins.index_state_management.policy_id` index setting still
        exists but is deprecated, and it would not apply to indices a data
        stream rolls over on its own.
        """
        return {}

    @property
    def client(self) -> AsyncOpenSearch:
        """The underlying client, for OpenSearch-specific tooling and tests."""
        return self._client

    # --------------------------------------------------------------- liveness
    async def ping(self) -> bool:
        try:
            return bool(await self._client.ping())
        except Exception as exc:
            logger.warning("search_ping_failed", engine=self.name, error=str(exc))
            return False

    async def info(self) -> dict[str, Any]:
        with _translated():
            info = await self._client.info()
        version = info.get("version", {})
        return {
            "engine": self.name,
            "cluster_name": info.get("cluster_name"),
            # `distribution` distinguishes a real OpenSearch from an
            # Elasticsearch 7.10 fork answering the same API shape.
            "distribution": version.get("distribution", "unknown"),
            "version": str(version.get("number", "unknown")),
        }

    async def close(self) -> None:
        await self._client.close()
        logger.info("search_client_closed", engine=self.name)

    # ------------------------------------------------------------------ reads
    async def search(
        self,
        *,
        body: dict[str, Any],
        index: str | None = None,
        routing: str | None = None,
        ignore_unavailable: bool = False,
        allow_partial_results: bool | None = None,
        pre_filter_shard_size: int | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"body": body}
        if index is not None:
            kwargs["index"] = index
        if routing is not None:
            kwargs["routing"] = routing
        if ignore_unavailable:
            kwargs["ignore_unavailable"] = True
        if allow_partial_results is not None:
            kwargs["allow_partial_search_results"] = allow_partial_results
        if pre_filter_shard_size is not None:
            kwargs["pre_filter_shard_size"] = pre_filter_shard_size
        with _translated():
            response = await self._client.search(**kwargs)
        return dict(response)

    async def count(
        self,
        *,
        index: str,
        body: dict[str, Any],
        routing: str | None = None,
        ignore_unavailable: bool = False,
    ) -> int:
        kwargs: dict[str, Any] = {"index": index, "body": body}
        if routing is not None:
            kwargs["routing"] = routing
        if ignore_unavailable:
            kwargs["ignore_unavailable"] = True
        with _translated():
            response = await self._client.count(**kwargs)
        return int(response.get("count", 0))

    async def open_pit(self, *, index: str, keep_alive: str) -> str:
        with _translated():
            # `create_pit`, not `create_point_in_time`: the latter is deprecated
            # in opensearch-py 2.x and slated for removal.
            #
            # No `ignore_unavailable`, unlike the Elasticsearch adapter. It is
            # not a parameter of this API, and forcing it through the query
            # string does not help: over a missing index OpenSearch then answers
            # `illegal_argument_exception: invalid id: [null]` instead of
            # Elastic's empty point-in-time. Omitting it gives a clean
            # `index_not_found_exception` -> `SearchNotFound`, which is the
            # honest answer, and every export target is provisioned at bootstrap
            # anyway.
            response = await self._client.create_pit(
                index=index,
                keep_alive=keep_alive,
            )
        # OpenSearch answers with `pit_id`; Elasticsearch with `id`. Both are
        # accepted so a version that renames it does not break the export.
        pit_id = response.get("pit_id") or response.get("id")
        if not pit_id:
            raise SearchRejected(f"point-in-time response carried no id: {sorted(response)}")
        return str(pit_id)

    async def close_pit(self, pit_id: str) -> None:
        with _translated():
            await self._client.delete_pit(body={"pit_id": [pit_id]})

    # ----------------------------------------------------------------- writes
    async def bulk(
        self,
        operations: list[dict[str, Any]],
        *,
        refresh: bool | str = False,
    ) -> dict[str, Any]:
        with _translated():
            response = await self._client.bulk(body=operations, refresh=refresh)
        return dict(response)

    async def get_document(
        self,
        *,
        index: str,
        doc_id: str,
        source_includes: list[str] | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"index": index, "id": doc_id}
        if source_includes is not None:
            kwargs["_source_includes"] = ",".join(source_includes)
        with _translated():
            response = await self._client.get(**kwargs)
        return dict(response)

    async def index_document(
        self,
        *,
        index: str,
        doc_id: str,
        document: dict[str, Any],
        op_type: str | None = None,
        refresh: bool | str = False,
    ) -> None:
        kwargs: dict[str, Any] = {
            "index": index,
            "id": doc_id,
            "body": document,
            "refresh": refresh,
        }
        if op_type is not None:
            kwargs["op_type"] = op_type
        with _translated():
            await self._client.index(**kwargs)

    async def update_document(
        self,
        *,
        index: str,
        doc_id: str,
        doc: dict[str, Any],
        refresh: bool | str = False,
    ) -> dict[str, Any]:
        with _translated():
            response = await self._client.update(
                index=index,
                id=doc_id,
                body={"doc": doc},
                refresh=refresh,
            )
        return dict(response)

    # ------------------------------------------------------------ provisioning
    async def ensure_lifecycle_policy(
        self,
        *,
        name: str,
        retention: RetentionPolicy,
        index_patterns: tuple[str, ...],
    ) -> None:
        """Create or replace the ISM policy, and let it claim the patterns.

        ISM refuses a blind overwrite: updating an existing policy requires the
        sequence number and primary term it was last written with, so an
        existing policy is read first and the update is conditioned on them.
        Without that, every restart would fail with a version conflict.
        """
        policy = ism_policy(retention, index_patterns=index_patterns)
        path = f"{_ISM_POLICY_PATH}/{name}"

        existing: dict[str, Any] | None = None
        try:
            with _translated():
                existing = dict(await self._client.transport.perform_request("GET", path))
        except SearchNotFound:
            existing = None

        params: dict[str, Any] = {}
        if existing is not None:
            params = {
                "if_seq_no": existing.get("_seq_no"),
                "if_primary_term": existing.get("_primary_term"),
            }

        with _translated():
            await self._client.transport.perform_request(
                "PUT", path, params=params or None, body=policy
            )
        logger.info(
            "ism_policy_applied",
            policy=name,
            patterns=list(index_patterns),
            updated=existing is not None,
        )

    async def put_index_template(self, *, name: str, template: dict[str, Any]) -> None:
        with _translated():
            await self._client.indices.put_index_template(name=name, body=template)

    async def index_exists(self, *, index: str, include_hidden: bool = False) -> bool:
        kwargs: dict[str, Any] = {"index": index}
        if include_hidden:
            kwargs["expand_wildcards"] = "all"
        with _translated():
            return bool(await self._client.indices.exists(**kwargs))

    async def create_index(
        self,
        *,
        index: str,
        settings: dict[str, Any],
        mappings: dict[str, Any],
    ) -> None:
        with _translated():
            await self._client.indices.create(
                index=index, body={"settings": settings, "mappings": mappings}
            )

    async def data_stream_exists(self, *, name: str) -> bool:
        try:
            with _translated():
                response = await self._client.indices.get_data_stream(name=name)
        except SearchNotFound:
            return False
        return bool(dict(response).get("data_streams"))

    async def create_data_stream(self, *, name: str) -> None:
        with _translated():
            await self._client.indices.create_data_stream(name=name)


# ---------------------------------------------------------------------------
# ISM policy - OpenSearch-specific, so it lives with the adapter
# ---------------------------------------------------------------------------
def ism_policy(
    retention: RetentionPolicy,
    *,
    index_patterns: tuple[str, ...],
) -> dict[str, Any]:
    """The ILM phases, expressed as ISM states and transitions.

    Same intent as `elastic.ilm_policy`, different vocabulary: ILM's phases with
    `min_age` become named states whose transitions carry `min_index_age`, and
    the actions are renamed (`forcemerge` -> `force_merge`, `readonly` ->
    `read_only`, `allocate` -> `replica_count`, `set_priority` ->
    `index_priority`).

    The delete state is the *maximum* retention permitted, never the mechanism
    for honouring an erasure request - those are served by crypto-shredding,
    which leaves the record and its hash in place.

    `ism_template` is what attaches the policy to new indices, including the
    backing indices a data stream creates on rollover. Its priority sits above
    the default so a stray broader policy cannot claim audit indices.
    """
    return {
        "policy": {
            "description": (
                "EveryCRED audit retention. The delete state is the regulatory "
                "maximum; erasure requests are served by crypto-shredding."
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {"index_priority": {"priority": 100}},
                        {
                            "rollover": {
                                "min_primary_shard_size": (
                                    retention.rollover_max_primary_shard_size
                                ),
                                "min_index_age": retention.rollover_max_age,
                            }
                        },
                    ],
                    "transitions": [{"state_name": "warm", "conditions": {"min_index_age": "30d"}}],
                },
                {
                    "name": "warm",
                    "actions": [
                        # Read-only plus a single segment: the best search
                        # latency and disk footprint available for immutable
                        # data.
                        {"force_merge": {"max_num_segments": 1}},
                        {"read_only": {}},
                        {"index_priority": {"priority": 50}},
                    ],
                    "transitions": [
                        {"state_name": "cold", "conditions": {"min_index_age": "180d"}}
                    ],
                },
                {
                    "name": "cold",
                    "actions": [
                        # Replicas drop to 0: durability comes from the S3 WORM
                        # archive and cluster snapshots, so paying for a second
                        # copy of five-year-old data is waste.
                        {"replica_count": {"number_of_replicas": 0}},
                        {"index_priority": {"priority": 0}},
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {"min_index_age": f"{retention.retention_days}d"},
                        }
                    ],
                },
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [
                {
                    "index_patterns": list(index_patterns),
                    "priority": 100,
                }
            ],
        }
    }
