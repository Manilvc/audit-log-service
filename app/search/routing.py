"""Hybrid user -> data stream routing.

Every user writes to the shared data stream by default. A user listed in
`DEDICATED_USERS` gets its own stream instead, which is how a high-volume or
contractually-isolated user is handled without sharding the cluster per
customer.

Two rules keep this safe:

* **Write routing is derived, never supplied.** A caller cannot name a target
  index; the target is computed from the authenticated user uuid. That removes
  cross-user writes as a class of bug.
* **Read routing follows the same function.** A user search resolves to the
  same one or two streams it writes to, never a wildcard over the cluster, so
  the query cannot accidentally span users.

Promoting a user mid-life is supported: reads then cover both the dedicated
stream and the shared one, so history written before the promotion stays
visible. That is why `read_targets` can return two names.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

#: User uuids reach us from a request header and end up inside an index name, so
#: they are validated rather than trusted. Anything outside this alphabet is
#: rejected before it can influence a URL path - the index-name equivalent of
#: SQL injection defence.
_USER_UUID_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

#: Elasticsearch forbids these in index names; the regex above already excludes
#: them, but the constant documents why the alphabet is so narrow.
_FORBIDDEN_IN_INDEX_NAMES: Final[str] = r'\/*?"<>| ,#:'


class InvalidUserUuidError(ValueError):
    """The user uuid is missing or not shaped like a user uuid."""


@dataclass(frozen=True, slots=True)
class RouteDecision:
    """Where a user's events are written and read."""

    user_uuid: str
    write_target: str
    """Data stream that receives new documents."""
    read_targets: tuple[str, ...]
    """Streams a read must cover, most specific first."""
    dedicated: bool
    routing_key: str | None
    """Shard routing value. None for dedicated streams, where the stream is
    already user-scoped and pinning to one shard would only remove headroom."""


class UserRouter:
    """Resolves the data streams for a user. Pure, cheap, no I/O."""

    def __init__(
        self,
        *,
        shared_stream: str,
        index_prefix: str,
        dedicated_users: frozenset[str],
        custom_routing: bool = True,
    ) -> None:
        self._shared = shared_stream
        self._prefix = index_prefix
        self._dedicated = dedicated_users
        # Whether the configured engine accepts a routing value on a data stream
        # write. `SearchBackend.supports_custom_routing` is the authority; the
        # default keeps every existing caller on Elasticsearch behaviour.
        self._custom_routing = custom_routing

    # ------------------------------------------------------------- validation
    @staticmethod
    def validate_user_uuid(user_uuid: str | None) -> str:
        """Return a user uuid that is safe to interpolate into an index name.

        Raises:
            InvalidUserUuidError: empty, over-long, or containing a character
                Elasticsearch would reject or that could traverse a URL path.
        """
        if not user_uuid:
            raise InvalidUserUuidError("user_uuid is required")
        candidate = user_uuid.strip()
        if not _USER_UUID_RE.match(candidate):
            raise InvalidUserUuidError(
                "user_uuid must be 1-63 chars of [A-Za-z0-9._-] starting "
                "alphanumeric (rejects characters illegal in an index name: "
                f"{_FORBIDDEN_IN_INDEX_NAMES})"
            )
        return candidate

    # ---------------------------------------------------------------- routing
    def dedicated_stream_name(self, user_uuid: str) -> str:
        """Name of a user's dedicated stream.

        The `-u-` infix keeps the dedicated pattern (`audit-u-*`) disjoint from
        the shared stream (`audit-shared`), so the two index templates can never
        both match one stream.
        """
        return f"{self._prefix}-u-{user_uuid.lower()}"

    def dedicated_pattern(self) -> str:
        return f"{self._prefix}-u-*"

    def shared_pattern(self) -> str:
        return self._shared

    def is_dedicated(self, user_uuid: str) -> bool:
        return user_uuid in self._dedicated

    def resolve(self, user_uuid: str | None) -> RouteDecision:
        """Resolve write and read targets for one user."""
        validated = self.validate_user_uuid(user_uuid)

        if self.is_dedicated(validated):
            stream = self.dedicated_stream_name(validated)
            return RouteDecision(
                user_uuid=validated,
                write_target=stream,
                # The shared stream is still read: it holds everything written
                # before this user was promoted.
                read_targets=(stream, self._shared),
                dedicated=True,
                routing_key=None,
            )

        return RouteDecision(
            user_uuid=validated,
            write_target=self._shared,
            read_targets=(self._shared,),
            dedicated=False,
            # Pins the user to one shard, so its searches fan out to a single
            # shard instead of all of them - where the engine allows it. An
            # OpenSearch data stream rejects a routed write outright, so the key
            # is omitted there and searches fan out. Isolation is unaffected:
            # that comes from the mandatory user filter, not from routing.
            routing_key=validated if self._custom_routing else None,
        )

    def cross_user_read_targets(self) -> tuple[str, ...]:
        """Targets for an authorised cross-user query.

        Reachable only with the `audit:cross_user` scope, and the attempt is
        itself audited as `audit_log.cross_user_access` at CRITICAL severity.
        """
        return (self.shared_pattern(), self.dedicated_pattern())

    def partition_for(self, user_uuid: str, partitions: int) -> int:
        """Stable queue partition for a user.

        The hash chain is per (user, partition), so a user must always land
        on the same partition or its sequence numbers would interleave across
        chains. `hash()` is unusable here - Python randomises string hashing per
        process, so two workers would disagree. A fixed digest does not.
        """
        if partitions < 1:
            raise ValueError("partitions must be >= 1")
        digest = _stable_digest(user_uuid)
        return digest % partitions

    def chain_id(self, user_uuid: str, partition: int) -> str:
        """Identifier of the hash chain a user's events belong to."""
        return f"{user_uuid}:{partition}"


def _stable_digest(value: str) -> int:
    """Process-independent 64-bit digest of a string."""
    import hashlib

    return int.from_bytes(hashlib.blake2b(value.encode(), digest_size=8).digest(), "big")
