"""The search backend port.

Everything the audit trail needs from a search engine, named by intent rather
than after one vendor's client. Adapters implement it - Elasticsearch today,
OpenSearch alongside it - and nothing above this package knows which is running.

Why a port rather than swapping one client for another
------------------------------------------------------
The engines are compatible in the middle and incompatible at the edges. The
query DSL, `search_after` pagination, bulk writes and `op_type: create`
idempotency are identical, and that is the bulk of the search code - it stays
shared. What differs is exactly what an adapter is for:

* **The client library.** `elasticsearch` 8.x verifies the `X-Elastic-Product`
  response header and refuses to talk to anything that is not Elasticsearch, so
  pointing it at OpenSearch fails on the first request. There is no toggle.
* **Lifecycle management.** ILM (`_ilm/policy`, `index.lifecycle.name`) has no
  counterpart in OpenSearch, which uses the ISM plugin with a different policy
  document. `ensure_lifecycle_policy` takes retention *intent*, and each adapter
  renders its own document from it.
* **Three field types.** `flattened`, `match_only_text` and `constant_keyword`
  are Elastic types. `FieldTypes` carries the per-engine equivalents so
  `mappings.py` stays engine-neutral.
* **Point-in-time.** The same idea, under different call names and body shapes.

The port is deliberately narrow - it has exactly the operations that
`repository.py`, `keyring.py` and `bootstrap.py` actually call. A port shaped
like the whole client would leave every adapter faking methods nobody uses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class FieldTypes:
    """The mapping types that differ between engines.

    Everything else in the event mapping - `keyword`, `date`, `long`,
    `boolean`, `object` - is identical on both, so only the divergent three are
    abstracted here. Each adapter supplies its own set; `mappings.py` reads them
    and never names an engine.
    """

    subtree: dict[str, Any]
    """For `labels`, `change.before` and `change.after`: index a whole JSON
    subtree as one field, so an emitter can add a key without a mapping change
    and without `dynamic: strict` rejecting the document. Elastic `flattened`;
    OpenSearch `flat_object`, whose query semantics are narrower - term lookups
    on dotted paths work, ranges and some aggregations do not."""

    log_text: dict[str, Any]
    """For `message`: free text that is searched but never scored or aggregated.
    Elastic `match_only_text` drops norms and positions, a large disk saving
    across six years of retention; OpenSearch has no equivalent and pays for
    plain `text`."""

    pinned_tenant: dict[str, Any]
    """For `tenant.id` on a *dedicated* stream, where every document belongs to
    one tenant by construction. Elastic `constant_keyword` makes the engine
    itself reject a document carrying the wrong tenant id - a storage-level
    backstop beneath the application's tenant filter (`docs/SECURITY.md`). An
    engine without it degrades to plain `keyword`, and the backstop then has to
    be re-established in the worker rather than quietly lost."""


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Retention and rollover intent, before either engine's policy document.

    The delete phase is the *maximum* retention permitted, never the mechanism
    for honouring an erasure request - those are served by crypto-shredding,
    which leaves the record and its hash in place.
    """

    retention_days: int
    rollover_max_primary_shard_size: str
    rollover_max_age: str


@runtime_checkable
class SearchBackend(Protocol):
    """The search engine, as this service uses it."""

    # --------------------------------------------------------------- identity
    @property
    def name(self) -> str:
        """Engine name, for logs, the dependency report and the startup line."""
        ...

    @property
    def field_types(self) -> FieldTypes:
        """Mapping types for this engine's event mapping."""
        ...

    @property
    def sort_date_format(self) -> str | None:
        """Date format for a `@timestamp` sort clause, or None to omit it.

        Elasticsearch returns the sort value formatted rather than as epoch
        millis, which is what `search_after` then carries. OpenSearch rejects
        the key outright - `x_content_parse_exception: [field_sort] unknown
        field [format]` - so it is omitted there and the cursor carries epoch
        millis instead. Either way the value round-trips within one engine,
        which is all a cursor has to do.
        """
        ...

    @property
    def supports_custom_routing(self) -> bool:
        """Whether a write to a data stream may carry a routing value.

        Elasticsearch allows it when the template opts in, and this service uses
        it to pin a shared tenant to one shard: a tenant-scoped search then hits
        one shard instead of fanning out across all of them.

        OpenSearch data streams refuse it outright - an indexing request with a
        routing value is rejected with `illegal_argument_exception: index request
        targeting data stream [...] specifies a custom routing`. So on that
        engine `TenantRouter` issues no routing key and searches fan out. That is
        a performance difference, not a correctness one: the mandatory tenant
        filter is what isolates tenants, and it is unaffected.
        """
        ...

    def lifecycle_index_settings(self, policy_name: str) -> dict[str, Any]:
        """Index settings that attach a new index to the retention policy.

        Elasticsearch resolves this through the template
        (`index.lifecycle.name`); OpenSearch attaches an ISM policy instead. An
        engine needing no per-index setting returns an empty mapping.
        """
        ...

    # --------------------------------------------------------------- liveness
    async def ping(self) -> bool:
        """True if the store answers. Never raises - readiness probes call it."""
        ...

    async def info(self) -> dict[str, Any]:
        """Cluster name, version and health, for the dependency report."""
        ...

    async def close(self) -> None:
        """Release the connection pool on shutdown."""
        ...

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
        """Run a search.

        `index` is omitted for a point-in-time search, which carries its own
        targets inside the PIT.
        """
        ...

    async def count(
        self,
        *,
        index: str,
        body: dict[str, Any],
        routing: str | None = None,
        ignore_unavailable: bool = False,
    ) -> int:
        """Number of matching documents."""
        ...

    async def open_pit(self, *, index: str, keep_alive: str) -> str:
        """Open a point-in-time and return its id."""
        ...

    async def close_pit(self, pit_id: str) -> None:
        """Release a PIT.

        A leaked one pins Lucene segments and blocks disk reclamation, so
        callers run this on the error path too.

        Raises:
            SearchNotFound: already released or expired.
        """
        ...

    # ----------------------------------------------------------------- writes
    async def bulk(
        self,
        operations: list[dict[str, Any]],
        *,
        refresh: bool | str = False,
    ) -> dict[str, Any]:
        """Apply a bulk body.

        The raw response comes back because the caller reports per-item
        outcomes to the emitter, by index within the batch it sent.
        """
        ...

    async def get_document(
        self,
        *,
        index: str,
        doc_id: str,
        source_includes: list[str] | None = None,
    ) -> dict[str, Any]:
        """Fetch one document by id.

        Raises:
            SearchNotFound: no such document.
        """
        ...

    async def index_document(
        self,
        *,
        index: str,
        doc_id: str,
        document: dict[str, Any],
        op_type: str | None = None,
        refresh: bool | str = False,
    ) -> None:
        """Write one document at a known id.

        Raises:
            SearchConflict: `op_type="create"` and the id already exists.
        """
        ...

    async def update_document(
        self,
        *,
        index: str,
        doc_id: str,
        doc: dict[str, Any],
        refresh: bool | str = False,
    ) -> dict[str, Any]:
        """Partially update one document.

        The response carries `result`, which distinguishes a real change from a
        no-op - that is how a repeated erasure request stays idempotent.

        Raises:
            SearchNotFound: no such document.
        """
        ...

    # ------------------------------------------------------------ provisioning
    async def ensure_lifecycle_policy(
        self,
        *,
        name: str,
        retention: RetentionPolicy,
        index_patterns: tuple[str, ...],
    ) -> None:
        """Create or replace the retention policy.

        `index_patterns` is what the policy should govern. Elasticsearch does
        not need it - ILM is attached per index through the template setting
        `lifecycle_index_settings` returns - but OpenSearch's ISM claims its
        indices by pattern from inside the policy document, so the port has to
        carry it.
        """
        ...

    async def put_index_template(self, *, name: str, template: dict[str, Any]) -> None:
        """Create or replace a composable index template."""
        ...

    async def index_exists(self, *, index: str, include_hidden: bool = False) -> bool:
        """True if a *concrete* index of that name exists."""
        ...

    async def create_index(
        self,
        *,
        index: str,
        settings: dict[str, Any],
        mappings: dict[str, Any],
    ) -> None:
        """Create a plain index.

        Raises:
            SearchConflict: it already exists - another replica won the race.
        """
        ...

    async def data_stream_exists(self, *, name: str) -> bool:
        """True if the data stream exists."""
        ...

    async def create_data_stream(self, *, name: str) -> None:
        """Create a data stream.

        Raises:
            SearchConflict: it already exists.
            SearchRejected: no matching index template, among other causes.
        """
        ...
