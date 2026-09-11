"""Issuing, verifying and revoking the API keys that emitters authenticate with.

Two planes, deliberately separated:

* **Admin plane** - the keys in `SERVICE_API_KEYS`. Rotated by deploy, hold every
  scope, and are the only credential that may mint or revoke other keys.
* **Ingest plane** - keys issued through this service. Each is bound to one
  user and one emitting domain, holds `audit:write` unless narrowed, and can be
  revoked in seconds without a deploy.

That split is what makes per-emitter credentials safe to hand out: a leaked
ingest key can write events for one user and nothing else - it cannot read the
trail, cannot erase a data subject, and cannot reach another user.

Why a digest and not bcrypt
---------------------------
A password hash is slow on purpose because a human password has perhaps 30 bits
of entropy. These secrets carry 256 bits from `secrets.token_urlsafe`, so there
is nothing to brute force and the slowness would buy nothing - it would only add
tens of milliseconds to every audit write. A peppered SHA-256 with a constant
time comparison is the right shape here, and the pepper means a database dump
alone is not enough to test candidate keys offline.

Verification stays off the network on the hot path: a verified key is cached for
`API_KEY_CACHE_TTL_SECONDS`, which is also the worst case delay before a
revocation reaches an already warm replica.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from app.core.constants import (
    API_KEY_CACHE_MAX_ENTRIES,
    API_KEY_HINT_LENGTH,
    API_KEY_ID_BYTES,
    API_KEY_PART_COUNT,
    API_KEY_PREFIX,
    API_KEY_SECRET_BYTES,
    API_KEY_SEPARATOR,
    API_KEY_STATUS_ACTIVE,
    DEFAULT_ISSUED_KEY_SCOPES,
    FORBIDDEN_ISSUED_KEY_SCOPES,
)
from app.core.logging import get_logger
from app.domain.enums import Scope
from app.search.api_key_store import DIGEST_SCHEME_SHA256, ApiKeyRecord, ApiKeyStore

logger = get_logger(__name__)

#: Returned by `issue`, and the only moment the secret exists outside the
#: caller's own storage. It is never persisted and never logged.
MINTED_KEY_LOG_FIELDS: Final[tuple[str, ...]] = ("key_id", "user_uuid", "domain")


class ApiKeyError(Exception):
    """A key could not be issued or revoked as asked."""


@dataclass(frozen=True, slots=True)
class MintedApiKey:
    """A freshly issued key: the record, plus the one-time plaintext."""

    record: ApiKeyRecord
    plaintext: str


@dataclass(frozen=True, slots=True)
class _CachedKey:
    """A verified key held in memory until `expires_at_monotonic`."""

    record: ApiKeyRecord
    expires_at_monotonic: float


def build_key_id() -> str:
    """Opaque identifier that doubles as the store's document id.

    Hex, not url-safe base64: `token_urlsafe` emits `-` and `_`, and an
    underscore here would collide with the separator and make the key
    unparseable. The secret can contain one because it is the final field.
    """
    return secrets.token_hex(API_KEY_ID_BYTES)


def build_key_secret() -> str:
    """The secret half of a key. 256 bits, so guessing is not a threat model."""
    return secrets.token_urlsafe(API_KEY_SECRET_BYTES)


def format_api_key(key_id: str, secret: str) -> str:
    """Assemble the string an emitter puts in `x-api-key`.

    `evcaud_<key_id>_<secret>` - the marker makes a leaked key recognisable to a
    secret scanner, and the embedded id turns verification into a point lookup.
    """
    return API_KEY_SEPARATOR.join((API_KEY_PREFIX, key_id, secret))


def parse_api_key(presented: str) -> tuple[str, str] | None:
    """Split a presented key into (key_id, secret), or None if it is not one.

    Returning None rather than raising keeps the caller's flow simple: a string
    that is not an issued key is not an error, it is an env-configured admin key
    or a typo, and both are handled by the authenticator.
    """
    if not presented:
        return None
    # Bounded split: the secret is url-safe base64 and may legitimately contain
    # the separator, so everything after the second one is the secret.
    parts = presented.split(API_KEY_SEPARATOR, API_KEY_PART_COUNT - 1)
    if len(parts) != API_KEY_PART_COUNT:
        return None
    prefix, key_id, secret = parts
    if prefix != API_KEY_PREFIX or not key_id or not secret:
        return None
    return key_id, secret


def build_secret_digest(secret: str, *, pepper: str) -> str:
    """Peppered SHA-256 of the secret, hex encoded.

    HMAC rather than a plain hash of pepper+secret: it is the construction built
    for keyed digests, and it sidesteps length-extension entirely.
    """
    return hmac.new(pepper.encode(), secret.encode(), hashlib.sha256).hexdigest()


def resolve_requested_scopes(requested: tuple[str, ...] | None) -> tuple[str, ...]:
    """Narrow the scopes an issued key may hold.

    Defaults to write-only, and refuses the three that reach across users or
    destroy data whatever the request asks for.

    Raises:
        ApiKeyError: an unknown scope, or one of the forbidden three.
    """
    scopes = tuple(requested) if requested else DEFAULT_ISSUED_KEY_SCOPES
    known = {scope.value for scope in Scope}

    unknown = sorted(set(scopes) - known)
    if unknown:
        raise ApiKeyError(f"unknown scope(s): {', '.join(unknown)}")

    forbidden = sorted(set(scopes) & FORBIDDEN_ISSUED_KEY_SCOPES)
    if forbidden:
        raise ApiKeyError(
            f"scope(s) {', '.join(forbidden)} cannot be delegated to an issued key; "
            "they stay with the service credential rotated by deploy"
        )
    return scopes


def resolve_expiry(now: datetime, *, requested_days: int | None, default_days: int) -> datetime:
    """When the key stops working.

    Always bounded: an audit-ingest credential that never expires is one nobody
    remembers to rotate. `default_days` comes from configuration so a deployment
    can be stricter than the caller asked.
    """
    days = requested_days if requested_days and requested_days > 0 else default_days
    return now + timedelta(days=days)


class _VerifiedKeyCache:
    """Bounded, time-limited cache of verified key records.

    Keyed by key id. Bounded so a burst of distinct credentials cannot grow the
    heap; time-limited so a revocation takes effect without a restart.
    """

    def __init__(self, *, ttl_seconds: int, max_entries: int) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._entries: dict[str, _CachedKey] = {}

    def get(self, key_id: str) -> ApiKeyRecord | None:
        cached = self._entries.get(key_id)
        if cached is None:
            return None
        if time.monotonic() >= cached.expires_at_monotonic:
            self._entries.pop(key_id, None)
            return None
        return cached.record

    def put(self, record: ApiKeyRecord) -> None:
        if len(self._entries) >= self._max_entries:
            # Plain FIFO eviction: the access pattern is "a handful of emitters,
            # each hot", so an LRU's bookkeeping would not pay for itself.
            self._entries.pop(next(iter(self._entries)), None)
        self._entries[record.key_id] = _CachedKey(
            record=record,
            expires_at_monotonic=time.monotonic() + self._ttl_seconds,
        )

    def invalidate(self, key_id: str) -> None:
        self._entries.pop(key_id, None)


class ApiKeyService:
    """Issues, verifies and revokes ingest credentials."""

    def __init__(
        self,
        store: ApiKeyStore,
        *,
        pepper: str,
        cache_ttl_seconds: int,
        default_expiry_days: int,
    ) -> None:
        self._store = store
        self._pepper = pepper
        self._default_expiry_days = default_expiry_days
        self._cache = _VerifiedKeyCache(
            ttl_seconds=cache_ttl_seconds,
            max_entries=API_KEY_CACHE_MAX_ENTRIES,
        )

    # ----------------------------------------------------------------- issue
    async def issue(
        self,
        *,
        user_uuid: str,
        domain: str,
        label: str,
        created_by: str,
        requested_scopes: tuple[str, ...] | None = None,
        expires_in_days: int | None = None,
    ) -> MintedApiKey:
        """Mint a key for one user and one emitting domain.

        The plaintext is returned once and never stored: the record holds only a
        peppered digest and a six-character hint. A caller who loses it issues a
        new key and revokes the old one, which is the behaviour you want anyway.

        Raises:
            ApiKeyError: the requested scopes are unknown or not delegable.
        """
        scopes = resolve_requested_scopes(requested_scopes)
        now = datetime.now(UTC)
        key_id = build_key_id()
        secret = build_key_secret()

        record = ApiKeyRecord(
            key_id=key_id,
            user_uuid=user_uuid,
            domain=domain,
            label=label,
            secret_digest=build_secret_digest(secret, pepper=self._pepper),
            digest_scheme=DIGEST_SCHEME_SHA256,
            scopes=scopes,
            status=API_KEY_STATUS_ACTIVE,
            created_at=now,
            created_by=created_by,
            expires_at=resolve_expiry(
                now,
                requested_days=expires_in_days,
                default_days=self._default_expiry_days,
            ),
        )
        await self._store.create(record)
        return MintedApiKey(record=record, plaintext=format_api_key(key_id, secret))

    # ---------------------------------------------------------------- verify
    async def verify(self, presented: str) -> ApiKeyRecord | None:
        """Resolve a presented key to its record, or None if it cannot be used.

        None covers every failure the caller may not distinguish: not an issued
        key, no such id, wrong secret, revoked, expired. The reason is logged;
        the response says only that authentication failed.
        """
        parsed = parse_api_key(presented)
        if parsed is None:
            return None
        key_id, secret = parsed

        record = self._cache.get(key_id) or await self._load_and_cache(key_id)
        if record is None:
            return None
        if not self._secret_matches(record, secret):
            logger.warning("api_key_secret_mismatch", key_id=key_id)
            return None

        now = datetime.now(UTC)
        if not record.is_usable(now):
            logger.warning(
                "api_key_unusable",
                key_id=key_id,
                revoked=record.is_revoked,
                expired=record.is_expired(now),
            )
            return None
        return record

    async def _load_and_cache(self, key_id: str) -> ApiKeyRecord | None:
        """Read a key from the store and remember it for the cache window."""
        record = await self._store.get(key_id)
        if record is None:
            logger.warning("api_key_unknown", key_id=key_id)
            return None
        self._cache.put(record)
        return record

    def _secret_matches(self, record: ApiKeyRecord, secret: str) -> bool:
        """Constant-time comparison of the presented secret against the record."""
        candidate = build_secret_digest(secret, pepper=self._pepper)
        return hmac.compare_digest(candidate, record.secret_digest)

    # ----------------------------------------------------------- manage keys
    async def revoke(self, key_id: str, *, revoked_by: str) -> ApiKeyRecord | None:
        """Revoke a key and drop it from this process's cache.

        Other replicas stop honouring it within the cache TTL. If that window
        matters during an incident, restart them - the store is already updated.
        """
        record = await self._store.revoke(key_id, revoked_by=revoked_by)
        self._cache.invalidate(key_id)
        return record

    async def list_for_user(self, user_uuid: str, *, size: int) -> list[ApiKeyRecord]:
        """Keys issued to one user, newest first. Never includes a secret."""
        return await self._store.list_for_user(user_uuid, size=size)

    async def get_for_user(self, key_id: str, *, user_uuid: str) -> ApiKeyRecord | None:
        """One key, but only if it belongs to this user.

        A key id from another user reads as "no such key". Without that, the
        management endpoints would confirm which ids exist elsewhere.
        """
        record = await self._store.get(key_id)
        if record is None or record.user_uuid != user_uuid:
            return None
        return record


def to_scopes(record: ApiKeyRecord) -> frozenset[Scope]:
    """The record's scope strings as domain scopes.

    Unknown values are dropped rather than raising: a key written by a newer
    build that knew a scope this one does not should still authenticate, with
    less authority - failing closed on the scope, not on the request.
    """
    known = {scope.value: scope for scope in Scope}
    return frozenset(known[value] for value in record.scopes if value in known)


def build_key_hint(plaintext: str) -> str:
    """Last few characters of a key, for recognising it in a list.

    Taken from the end rather than the start: every key shares the same prefix
    and id length, so the tail is the part that distinguishes them.
    """
    return plaintext[-API_KEY_HINT_LENGTH:]
