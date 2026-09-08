"""Elasticsearch adapter for the search port.

Everything Elastic-specific lives here: the client library, ILM, the three
Elastic field types, and the translation of client exceptions into the port's
own errors. The behaviour is exactly what the service did before the port
existed - this adapter is a move, not a rewrite.

Two quirks are worth knowing about, because both cost real debugging time:

* ``GET /_data_stream/<name>`` answers **200 with an empty list** for a stream
  that does not exist, not 404. Checking the status alone reports every missing
  stream as present, so `data_stream_exists` inspects the body.
* ``resource_already_exists_exception`` arrives as a 400, not a 409. It means
  another replica won a create race, so it is translated to `SearchConflict`
  where the caller can treat it as success.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final

from elasticsearch import (
    ApiError,
    AsyncElasticsearch,
    BadRequestError,
    ConflictError,
    NotFoundError,
    TransportError,
)

from app.core.logging import get_logger
from app.search.backends.base import FieldTypes, RetentionPolicy
from app.search.backends.errors import (
    SearchConflict,
    SearchNotFound,
    SearchRejected,
    SearchUnavailable,
)

logger = get_logger(__name__)

#: Elastic's own types for the three fields that have no cross-engine
#: equivalent. See `FieldTypes` for what each one is for and what it costs.
ELASTIC_FIELD_TYPES: Final[FieldTypes] = FieldTypes(
    subtree={"type": "flattened"},
    log_text={"type": "match_only_text"},
    pinned_tenant={"type": "constant_keyword"},
)

#: Marks a create that lost a race. Elasticsearch reports it as a 400 rather
#: than a 409, so the string is the only reliable discriminator.
_ALREADY_EXISTS: Final[str] = "resource_already_exists_exception"


@contextlib.contextmanager
def _translated() -> Iterator[None]:
    """Map client exceptions onto the port's errors.

    Ordering matters: the specific status errors are subclasses of `ApiError`,
    and `TransportError` is a separate hierarchy covering "never reached the
    cluster" - which is the one worth retrying.
    """
    try:
        yield
    except NotFoundError as exc:
        raise SearchNotFound(str(exc)) from exc
    except ConflictError as exc:
        raise SearchConflict(str(exc)) from exc
    except BadRequestError as exc:
        if _ALREADY_EXISTS in str(exc):
            raise SearchConflict(str(exc)) from exc
        raise SearchRejected(str(exc)) from exc
    except ApiError as exc:
        raise SearchRejected(str(exc)) from exc
    except TransportError as exc:
        raise SearchUnavailable(str(exc)) from exc


def _client_major() -> str:
    """Major version of the installed client, for the mismatch warning.

    Read from package metadata rather than hardcoded: a pin change would
    otherwise leave this warning asserting a version nobody is running, which
    is worse than no warning at all.
    """
    try:
        return version("elasticsearch").split(".")[0]
    except PackageNotFoundError:  # pragma: no cover - only outside a venv
        return "unknown"


class ElasticsearchBackend:
    """The search port, backed by Elasticsearch."""

    def __init__(self, client: AsyncElasticsearch) -> None:
        self._client = client

    # --------------------------------------------------------------- identity
    @property
    def name(self) -> str:
        return "elasticsearch"

    @property
    def field_types(self) -> FieldTypes:
        return ELASTIC_FIELD_TYPES

    @property
    def sort_date_format(self) -> str | None:
        return "strict_date_optional_time"

    @property
    def supports_custom_routing(self) -> bool:
        """Yes, when the data stream template opts in with `allow_custom_routing`."""
        return True

    def lifecycle_index_settings(self, policy_name: str) -> dict[str, Any]:
        """ILM attaches through the index settings in the template."""
        return {"lifecycle": {"name": policy_name}}

    @property
    def client(self) -> AsyncElasticsearch:
        """The underlying client.

        For Elastic-specific tooling and the integration suite, which asserts on
        guarantees the *engine* enforces - a strict mapping rejecting an unknown
        field, `constant_keyword` rejecting a foreign tenant id. Nothing in the
        request path should reach for this.
        """
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
        cluster_version = str(info.get("version", {}).get("number", "unknown"))
        major = cluster_version.split(".")[0] if cluster_version[:1].isdigit() else "unknown"
        client_major = _client_major()
        # A one-major gap is supported by the client's compatibility mode; two
        # is not, and the failure surfaces much later as confusing query errors.
        if major not in {"unknown", client_major} and abs(int(major) - int(client_major)) > 1:
            logger.warning(
                "search_version_mismatch",
                engine=self.name,
                cluster_version=cluster_version,
                client_major=client_major,
            )
        return {
            "engine": self.name,
            "cluster_name": info.get("cluster_name"),
            "version": cluster_version,
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
            response = await self._client.open_point_in_time(
                index=index,
                keep_alive=keep_alive,
                ignore_unavailable=True,
            )
        return str(response["id"])

    async def close_pit(self, pit_id: str) -> None:
        with _translated():
            await self._client.close_point_in_time(id=pit_id)

    # ----------------------------------------------------------------- writes
    async def bulk(
        self,
        operations: list[dict[str, Any]],
        *,
        refresh: bool | str = False,
    ) -> dict[str, Any]:
        with _translated():
            response = await self._client.bulk(operations=operations, refresh=refresh)
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
            kwargs["source_includes"] = source_includes
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
            "document": document,
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
                doc=doc,
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
        """`index_patterns` is unused here.

        ILM attaches per index through `index.lifecycle.name` in the template,
        so the policy itself names no patterns. The argument exists for
        OpenSearch, whose ISM policies claim their indices by pattern.
        """
        with _translated():
            await self._client.ilm.put_lifecycle(name=name, policy=ilm_policy(retention))

    async def put_index_template(self, *, name: str, template: dict[str, Any]) -> None:
        with _translated():
            await self._client.indices.put_index_template(name=name, **template)

    async def index_exists(self, *, index: str, include_hidden: bool = False) -> bool:
        kwargs: dict[str, Any] = {"index": index}
        if include_hidden:
            # Hidden and closed indices count: any of them occupying a data
            # stream's name blocks creating the stream.
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
            await self._client.indices.create(index=index, settings=settings, mappings=mappings)

    async def data_stream_exists(self, *, name: str) -> bool:
        """Inspect the response body, not just the status.

        Elasticsearch 9.x answers `GET /_data_stream/<name>` for a stream that
        does not exist with 200 and an empty `data_streams` list. Trusting the
        status alone reports every missing stream as present, so nothing is ever
        created - which defeats pre-provisioning a tenant's stream off the write
        path. The `SearchNotFound` branch stays because older versions do 404.
        """
        try:
            with _translated():
                response = await self._client.indices.get_data_stream(name=name)
        except SearchNotFound:
            return False
        return bool(response.get("data_streams"))

    async def create_data_stream(self, *, name: str) -> None:
        with _translated():
            await self._client.indices.create_data_stream(name=name)


# ---------------------------------------------------------------------------
# ILM policy - Elastic-specific, so it lives with the adapter
# ---------------------------------------------------------------------------
def ilm_policy(retention: RetentionPolicy) -> dict[str, Any]:
    """Hot -> warm -> cold -> delete lifecycle.

    The delete phase is the *maximum* retention permitted, not the mechanism for
    honouring erasure requests - those are served by crypto-shredding, which
    leaves the record in place. Deleting a record early would break the hash
    chain and destroy audit evidence.

    HIPAA 164.316(b)(2)(i) sets the six-year floor that `retention_days`
    defaults to.
    """
    return {
        "_meta": {
            "description": (
                "EveryCRED audit retention. Delete phase is the regulatory "
                "maximum; erasure requests are served by crypto-shredding."
            ),
            "managed_by": "everycred-audit-service",
        },
        "phases": {
            "hot": {
                "actions": {
                    "rollover": {
                        "max_primary_shard_size": retention.rollover_max_primary_shard_size,
                        "max_age": retention.rollover_max_age,
                    },
                    # Keep the hot tier's search priority high while it is still
                    # receiving writes.
                    "set_priority": {"priority": 100},
                }
            },
            "warm": {
                "min_age": "30d",
                "actions": {
                    # Read-only plus a single segment: the best search latency
                    # and disk footprint available for immutable data.
                    "forcemerge": {"max_num_segments": 1},
                    "readonly": {},
                    "set_priority": {"priority": 50},
                },
            },
            "cold": {
                "min_age": "180d",
                "actions": {
                    # Replicas drop to 0 in cold: durability comes from the S3
                    # WORM archive and cluster snapshots, so paying for a second
                    # copy of five-year-old data is waste.
                    "allocate": {"number_of_replicas": 0},
                    "set_priority": {"priority": 0},
                },
            },
            "delete": {
                "min_age": f"{retention.retention_days}d",
                "actions": {"delete": {"delete_searchable_snapshot": False}},
            },
        },
    }
