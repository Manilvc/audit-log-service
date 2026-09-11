"""Persistence for issued API keys, on whichever search store is configured.

A plain index rather than a data stream, for the same reason the keyring is:
a key record is mutable state - it gets revoked, its last-used timestamp moves -
while a data stream is append-only.

No secret is stored. The record holds a digest of the secret and a six-character
hint, so an operator can recognise a key in a list and nobody can reconstruct one
from a database dump.

Every read here is a point lookup by document id. That is deliberate: the ingest
path verifies a credential on every request, and a search would put a query
planner between an emitter and its audit write.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from app.core.constants import (
    API_KEY_LIST_MAX_SIZE,
    API_KEY_STATUS_ACTIVE,
    API_KEY_STATUS_REVOKED,
)
from app.core.logging import get_logger
from app.search.backends import SearchBackend, SearchConflict, SearchNotFound

logger = get_logger(__name__)

#: Written on create so a later read can tell which digest scheme produced
#: `secret_digest`, without which rotating the scheme would silently lock every
#: existing key out.
DIGEST_SCHEME_SHA256: Final[str] = "sha256-pepper-v1"


@dataclass(frozen=True, slots=True)
class ApiKeyRecord:
    """One issued key, as stored. Never carries the secret itself."""

    key_id: str
    user_uuid: str | None
    """The user this key may act for, or None when it is unbound.

    An unbound key takes its user from `x-audit-user-uuid` on each request, so
    one credential serves a backend that acts for every user. It is still
    scope-limited and revocable, which is what separates it from the
    env-configured admin key."""
    domain: str
    label: str
    secret_digest: str
    digest_scheme: str
    scopes: tuple[str, ...]
    status: str
    created_at: datetime
    created_by: str
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    last_used_at: datetime | None = None

    @property
    def is_revoked(self) -> bool:
        return self.status == API_KEY_STATUS_REVOKED

    @property
    def is_unbound(self) -> bool:
        """True when the request header decides the user rather than the key."""
        return self.user_uuid is None

    def is_expired(self, now: datetime) -> bool:
        """Whether the key's own expiry has passed."""
        return self.expires_at is not None and self.expires_at <= now

    def is_usable(self, now: datetime) -> bool:
        """Whether the key may authenticate a request at `now`."""
        return not self.is_revoked and not self.is_expired(now)


def _to_document(record: ApiKeyRecord) -> dict[str, Any]:
    """Render a record for storage, dates as ISO-8601 strings."""
    return {
        "key_id": record.key_id,
        "user_uuid": record.user_uuid,
        "domain": record.domain,
        "label": record.label,
        "secret_digest": record.secret_digest,
        "digest_scheme": record.digest_scheme,
        "scopes": list(record.scopes),
        "status": record.status,
        "created_at": record.created_at.isoformat(),
        "created_by": record.created_by,
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
        "revoked_by": record.revoked_by,
        "last_used_at": record.last_used_at.isoformat() if record.last_used_at else None,
    }


def _parse_timestamp(value: Any) -> datetime | None:
    """Read a stored ISO-8601 timestamp back, or None when absent."""
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _to_record(source: dict[str, Any]) -> ApiKeyRecord:
    """Rebuild a record from a stored document."""
    created_at = _parse_timestamp(source.get("created_at"))
    return ApiKeyRecord(
        key_id=str(source["key_id"]),
        user_uuid=(str(raw_user) if (raw_user := source.get("user_uuid")) else None),
        domain=str(source.get("domain", "")),
        label=str(source.get("label", "")),
        secret_digest=str(source["secret_digest"]),
        digest_scheme=str(source.get("digest_scheme", DIGEST_SCHEME_SHA256)),
        scopes=tuple(source.get("scopes", ())),
        status=str(source.get("status", API_KEY_STATUS_ACTIVE)),
        created_at=created_at or datetime.now(UTC),
        created_by=str(source.get("created_by", "unknown")),
        expires_at=_parse_timestamp(source.get("expires_at")),
        revoked_at=_parse_timestamp(source.get("revoked_at")),
        revoked_by=source.get("revoked_by"),
        last_used_at=_parse_timestamp(source.get("last_used_at")),
    )


class ApiKeyStore:
    """Reads and writes issued key records."""

    def __init__(self, backend: SearchBackend, *, index: str) -> None:
        self._store = backend
        self._index = index

    async def create(self, record: ApiKeyRecord) -> None:
        """Persist a newly issued key.

        `op_type=create` and `refresh=wait_for`: the key is handed to the caller
        the moment this returns, so it has to be readable by the very next
        request, and an id collision must never overwrite a live credential.

        Raises:
            SearchConflict: the generated id already exists.
        """
        await self._store.index_document(
            index=self._index,
            doc_id=record.key_id,
            document=_to_document(record),
            op_type="create",
            refresh="wait_for",
        )
        logger.info(
            "api_key_created",
            key_id=record.key_id,
            user_uuid=record.user_uuid,
            domain=record.domain,
            scopes=list(record.scopes),
        )

    async def get(self, key_id: str) -> ApiKeyRecord | None:
        """Fetch one key by id, or None when there is no such key."""
        try:
            response = await self._store.get_document(index=self._index, doc_id=key_id)
        except SearchNotFound:
            return None
        return _to_record(dict(response.get("_source", {})))

    async def revoke(self, key_id: str, *, revoked_by: str) -> ApiKeyRecord | None:
        """Mark a key revoked, keeping the record.

        Returns the updated record, or None when no such key exists. Revoking an
        already-revoked key is a no-op rather than an error, so a retried
        incident-response call is safe.
        """
        existing = await self.get(key_id)
        if existing is None:
            return None
        if existing.is_revoked:
            return existing

        revoked_at = datetime.now(UTC)
        await self._store.update_document(
            index=self._index,
            doc_id=key_id,
            doc={
                "status": API_KEY_STATUS_REVOKED,
                "revoked_at": revoked_at.isoformat(),
                "revoked_by": revoked_by,
            },
            refresh="wait_for",
        )
        logger.warning(
            "api_key_revoked",
            key_id=key_id,
            user_uuid=existing.user_uuid,
            domain=existing.domain,
            revoked_by=revoked_by,
        )
        return _to_record({**_to_document(existing), "status": API_KEY_STATUS_REVOKED})

    async def list_for_user(
        self,
        user_uuid: str,
        *,
        size: int = API_KEY_LIST_MAX_SIZE,
    ) -> list[ApiKeyRecord]:
        """Every key that can act for one user, newest first.

        Includes unbound keys, which can act for any user and therefore for
        this one.

        One query returns the whole page and the records are built from that
        response - there is no per-key lookup, because a list endpoint that
        queries once per row is how a management page becomes a load test.
        """
        response = await self._store.search(
            index=self._index,
            body={
                # This user's own keys, plus every unbound key - an unbound one
                # can write to this user's trail, so a management view that
                # hid it would understate who can reach these records.
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "bool": {
                                    "should": [
                                        {"term": {"user_uuid": user_uuid}},
                                        {"bool": {"must_not": {"exists": {"field": "user_uuid"}}}},
                                    ],
                                    "minimum_should_match": 1,
                                }
                            }
                        ]
                    }
                },
                "size": min(size, API_KEY_LIST_MAX_SIZE),
                "sort": [{"created_at": {"order": "desc"}}],
                "track_total_hits": False,
            },
            ignore_unavailable=True,
        )
        hits = response.get("hits", {}).get("hits", [])
        return [_to_record(dict(hit["_source"])) for hit in hits]

    async def touch_last_used(self, key_id: str, *, used_at: datetime) -> None:
        """Record that a key authenticated a request.

        Best effort and deliberately not on the hot path: a failure here must
        never fail an audit write, and the value is operational ("is this key
        still in use before I revoke it?") rather than evidential.
        """
        try:
            await self._store.update_document(
                index=self._index,
                doc_id=key_id,
                doc={"last_used_at": used_at.isoformat()},
                refresh=False,
            )
        except (SearchNotFound, SearchConflict) as exc:
            logger.warning("api_key_touch_failed", key_id=key_id, error=str(exc))
