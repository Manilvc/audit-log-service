"""Hybrid tenant -> data stream routing.

Every tenant writes to the shared data stream by default. A tenant listed in
`DEDICATED_TENANTS` gets its own stream instead, which is how a high-volume or
contractually-isolated tenant is handled without sharding the cluster per
customer.

Two rules keep this safe:

* **Write routing is derived, never supplied.** A caller cannot name a target
  index; the target is computed from the authenticated tenant id. That removes
  cross-tenant writes as a class of bug.
* **Read routing follows the same function.** A tenant search resolves to the
  same one or two streams it writes to, never a wildcard over the cluster, so
  the query cannot accidentally span tenants.

Promoting a tenant mid-life is supported: reads then cover both the dedicated
stream and the shared one, so history written before the promotion stays
visible. That is why `read_targets` can return two names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: Tenant ids reach us from a JWT claim and end up inside an index name, so they
#: are validated rather than trusted. Anything outside this alphabet is rejected
#: before it can influence a URL path - the index-name equivalent of SQL
#: injection defence.
_TENANT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

#: Elasticsearch forbids these in index names; the regex above already excludes
#: them, but the constant documents why the alphabet is so narrow.
_FORBIDDEN_IN_INDEX_NAMES: Final[str] = r'\/*?"<>| ,#:'


class InvalidTenantError(ValueError):
    """The tenant id is missing or not shaped like a tenant id."""


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """Where a tenant's events are written and read."""

    tenant_id: str
    write_target: str
    """Data stream that receives new documents."""
    read_targets: tuple[str, ...]
    """Streams a read must cover, most specific first."""
    dedicated: bool
    routing_key: str | None
    """Shard routing value. None for dedicated streams, where the stream is
    already tenant-scoped and pinning to one shard would only remove headroom."""


class TenantRouter:
    """Resolves the data streams for a tenant. Pure, cheap, no I/O."""

    def __init__(
        self,
        *,
        shared_stream: str,
        index_prefix: str,
        dedicated_tenants: frozenset[str],
    ) -> None:
        self._shared = shared_stream
        self._prefix = index_prefix
        self._dedicated = dedicated_tenants

    # ------------------------------------------------------------- validation
    @staticmethod
    def validate_tenant_id(tenant_id: str | None) -> str:
        """Return a tenant id that is safe to interpolate into an index name.

        Raises:
            InvalidTenantError: empty, over-long, or containing a character
                Elasticsearch would reject or that could traverse a URL path.
        """
        if not tenant_id:
            raise InvalidTenantError("tenant_id is required")
        candidate = tenant_id.strip()
        if not _TENANT_ID_RE.match(candidate):
            raise InvalidTenantError(
                "tenant_id must be 1-63 chars of [A-Za-z0-9._-] starting "
                "alphanumeric (rejects characters illegal in an index name: "
                f"{_FORBIDDEN_IN_INDEX_NAMES})"
            )
        return candidate

    # ---------------------------------------------------------------- routing
    def dedicated_stream_name(self, tenant_id: str) -> str:
        """Name of a tenant's dedicated stream.

        The `-t-` infix keeps the dedicated pattern (`audit-t-*`) disjoint from
        the shared stream (`audit-shared`), so the two index templates can never
        both match one stream.
        """
        return f"{self._prefix}-t-{tenant_id.lower()}"

    def dedicated_pattern(self) -> str:
        return f"{self._prefix}-t-*"

    def shared_pattern(self) -> str:
        return self._shared

    def is_dedicated(self, tenant_id: str) -> bool:
        return tenant_id in self._dedicated

    def resolve(self, tenant_id: str | None) -> RouteDecision:
        """Resolve write and read targets for one tenant."""
        validated = self.validate_tenant_id(tenant_id)

        if self.is_dedicated(validated):
            stream = self.dedicated_stream_name(validated)
            return RouteDecision(
                tenant_id=validated,
                write_target=stream,
                # The shared stream is still read: it holds everything written
                # before this tenant was promoted.
                read_targets=(stream, self._shared),
                dedicated=True,
                routing_key=None,
            )

        return RouteDecision(
            tenant_id=validated,
            write_target=self._shared,
            read_targets=(self._shared,),
            dedicated=False,
            # Pins the tenant to one shard, so its searches fan out to a single
            # shard instead of all of them.
            routing_key=validated,
        )

    def cross_tenant_read_targets(self) -> tuple[str, ...]:
        """Targets for an authorised cross-tenant query.

        Reachable only with the `audit:cross_tenant` scope, and the attempt is
        itself audited as `audit_log.cross_tenant_access` at CRITICAL severity.
        """
        return (self.shared_pattern(), self.dedicated_pattern())

    def partition_for(self, tenant_id: str, partitions: int) -> int:
        """Stable queue partition for a tenant.

        The hash chain is per (tenant, partition), so a tenant must always land
        on the same partition or its sequence numbers would interleave across
        chains. `hash()` is unusable here - Python randomises string hashing per
        process, so two workers would disagree. A fixed digest does not.
        """
        if partitions < 1:
            raise ValueError("partitions must be >= 1")
        digest = _stable_digest(tenant_id)
        return digest % partitions

    def chain_id(self, tenant_id: str, partition: int) -> str:
        """Identifier of the hash chain a tenant's events belong to."""
        return f"{tenant_id}:{partition}"


def _stable_digest(value: str) -> int:
    """Process-independent 64-bit digest of a string."""
    import hashlib

    return int.from_bytes(hashlib.blake2b(value.encode(), digest_size=8).digest(), "big")
