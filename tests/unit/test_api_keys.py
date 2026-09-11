"""Issued API keys: format, verification, scope limits and revocation.

The credential these tests cover is the one an emitter holds, so the properties
that matter are negative ones: a wrong secret must not authenticate, a revoked
key must stop working, and a key must never be able to widen its own authority.

Nothing here needs a cluster. The store is a dictionary, because what is being
tested is the service's decisions, not the engine's persistence - that is
covered end to end by the integration suite.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import (
    API_KEY_PREFIX,
    API_KEY_SEPARATOR,
    DEFAULT_ISSUED_KEY_SCOPES,
)
from app.domain.enums import Scope
from app.search.api_key_store import DIGEST_SCHEME_SHA256, ApiKeyRecord
from app.services.api_key_service import (
    ApiKeyError,
    ApiKeyService,
    build_key_hint,
    build_key_id,
    build_key_secret,
    build_secret_digest,
    format_api_key,
    parse_api_key,
    resolve_expiry,
    resolve_requested_scopes,
    to_scopes,
)

PEPPER = "unit-test-pepper"
USER = "user-a"
DOMAIN = "hrms.acme.example"


class FakeApiKeyStore:
    """The store as a dictionary, counting reads so caching can be asserted."""

    def __init__(self) -> None:
        self.records: dict[str, ApiKeyRecord] = {}
        self.reads = 0

    async def create(self, record: ApiKeyRecord) -> None:
        self.records[record.key_id] = record

    async def get(self, key_id: str) -> ApiKeyRecord | None:
        self.reads += 1
        return self.records.get(key_id)

    async def revoke(self, key_id: str, *, revoked_by: str) -> ApiKeyRecord | None:
        existing = self.records.get(key_id)
        if existing is None:
            return None
        revoked = replace(existing, status="revoked", revoked_by=revoked_by)
        self.records[key_id] = revoked
        return revoked

    async def list_for_user(self, user_uuid: str, *, size: int) -> list[ApiKeyRecord]:
        matching = [r for r in self.records.values() if r.user_uuid == user_uuid]
        return matching[:size]


@pytest.fixture
def store() -> FakeApiKeyStore:
    return FakeApiKeyStore()


@pytest.fixture
def service(store: FakeApiKeyStore) -> ApiKeyService:
    return ApiKeyService(
        store,  # type: ignore[arg-type]
        pepper=PEPPER,
        cache_ttl_seconds=60,
        default_expiry_days=365,
    )


# ---------------------------------------------------------------------------
# Key format
# ---------------------------------------------------------------------------
def test_a_key_round_trips_through_its_own_format() -> None:
    key_id, secret = build_key_id(), build_key_secret()
    assert parse_api_key(format_api_key(key_id, secret)) == (key_id, secret)


def test_a_secret_containing_the_separator_still_parses() -> None:
    """`token_urlsafe` emits underscores, and one used to break every key.

    The split is bounded to three parts, so everything after the second
    separator is the secret - and the id is hex, so it can never contain one.
    """
    secret = f"abc{API_KEY_SEPARATOR}def{API_KEY_SEPARATOR}ghi"
    key_id = build_key_id()

    assert parse_api_key(format_api_key(key_id, secret)) == (key_id, secret)
    assert API_KEY_SEPARATOR not in key_id


@pytest.mark.parametrize(
    "presented",
    [
        "",
        "not-a-key",
        "wrongprefix_abc_def",
        f"{API_KEY_PREFIX}_only-two-parts",
        f"{API_KEY_PREFIX}__missing-id",
    ],
)
def test_a_malformed_key_is_not_parsed(presented: str) -> None:
    """None rather than an exception: a string that is not an issued key may
    still be a valid env-configured one, and the caller tries that next."""
    assert parse_api_key(presented) is None


def test_the_hint_matches_the_end_of_the_key() -> None:
    """It is what lets an operator recognise a key in a list they cannot read."""
    plaintext = format_api_key(build_key_id(), build_key_secret())
    assert plaintext.endswith(build_key_hint(plaintext))


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------
def test_the_digest_is_stable_and_pepper_dependent() -> None:
    """Same secret, same pepper, same digest - and a stolen table is not enough.

    Without the pepper an attacker with a database dump could test candidate
    secrets offline; with it they need the process environment too.
    """
    secret = build_key_secret()
    assert build_secret_digest(secret, pepper=PEPPER) == build_secret_digest(secret, pepper=PEPPER)
    assert build_secret_digest(secret, pepper=PEPPER) != build_secret_digest(
        secret, pepper="a-different-pepper"
    )


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------
def test_an_issued_key_is_write_only_by_default() -> None:
    """An emitter stores events. A key that can also read can exfiltrate."""
    assert resolve_requested_scopes(None) == DEFAULT_ISSUED_KEY_SCOPES
    assert resolve_requested_scopes(None) == ("audit:write",)


def test_a_narrower_request_is_honoured() -> None:
    assert resolve_requested_scopes(("audit:write", "audit:read")) == (
        "audit:write",
        "audit:read",
    )


@pytest.mark.parametrize("scope", ["audit:erase", "audit:admin", "audit:cross_user"])
def test_the_dangerous_scopes_can_never_be_delegated(scope: str) -> None:
    """Erase destroys data, admin mints credentials, cross_user leaves the
    user boundary. All three stay with the key rotated by deploy."""
    with pytest.raises(ApiKeyError, match="cannot be delegated"):
        resolve_requested_scopes((scope,))


def test_an_unknown_scope_is_refused() -> None:
    with pytest.raises(ApiKeyError, match="unknown scope"):
        resolve_requested_scopes(("audit:invent",))


def test_unknown_stored_scopes_are_dropped_not_fatal() -> None:
    """A key written by a newer build should still work, with less authority."""
    record = _record(scopes=("audit:write", "audit:from-the-future"))
    assert to_scopes(record) == frozenset({Scope.WRITE})


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------
def test_expiry_falls_back_to_the_configured_default() -> None:
    """A credential that never expires is one nobody remembers to rotate."""
    now = datetime.now(UTC)
    assert resolve_expiry(now, requested_days=None, default_days=30) == now + timedelta(days=30)
    assert resolve_expiry(now, requested_days=0, default_days=30) == now + timedelta(days=30)
    assert resolve_expiry(now, requested_days=7, default_days=30) == now + timedelta(days=7)


# ---------------------------------------------------------------------------
# Issue and verify
# ---------------------------------------------------------------------------
def _record(**overrides: object) -> ApiKeyRecord:
    """A stored record with sensible defaults, for the pure-function tests."""
    base: dict[str, object] = {
        "key_id": build_key_id(),
        "user_uuid": USER,
        "domain": DOMAIN,
        "label": "",
        "secret_digest": "digest",
        "digest_scheme": DIGEST_SCHEME_SHA256,
        "scopes": ("audit:write",),
        "status": "active",
        "created_at": datetime.now(UTC),
        "created_by": "test",
    }
    return ApiKeyRecord(**{**base, **overrides})  # type: ignore[arg-type]


async def test_issuing_stores_a_digest_and_returns_the_secret_once(
    service: ApiKeyService, store: FakeApiKeyStore
) -> None:
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="HRMS", created_by="admin")
    stored = store.records[minted.record.key_id]

    assert minted.plaintext.startswith(f"{API_KEY_PREFIX}{API_KEY_SEPARATOR}")
    # The secret exists in the response and nowhere else.
    assert minted.plaintext not in stored.secret_digest
    assert stored.secret_digest != minted.plaintext
    assert stored.user_uuid == USER
    assert stored.expires_at is not None


async def test_a_freshly_issued_key_verifies(service: ApiKeyService) -> None:
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="", created_by="admin")
    verified = await service.verify(minted.plaintext)

    assert verified is not None
    assert verified.key_id == minted.record.key_id
    assert verified.user_uuid == USER


async def test_a_tampered_secret_does_not_verify(service: ApiKeyService) -> None:
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="", created_by="admin")
    key_id, secret = parse_api_key(minted.plaintext)  # type: ignore[misc]

    assert await service.verify(format_api_key(key_id, secret[:-1] + "x")) is None


async def test_an_unknown_key_does_not_verify(service: ApiKeyService) -> None:
    assert await service.verify(format_api_key(build_key_id(), build_key_secret())) is None


async def test_a_revoked_key_stops_verifying(
    service: ApiKeyService, store: FakeApiKeyStore
) -> None:
    """And the process cache is dropped, so it stops on this replica at once."""
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="", created_by="admin")
    assert await service.verify(minted.plaintext) is not None

    await service.revoke(minted.record.key_id, revoked_by="admin")
    assert await service.verify(minted.plaintext) is None


async def test_an_expired_key_does_not_verify(
    service: ApiKeyService, store: FakeApiKeyStore
) -> None:
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="", created_by="admin")
    expired = replace(minted.record, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    store.records[expired.key_id] = expired

    # Past the cache, because issuing does not warm it.
    assert await service.verify(minted.plaintext) is None


async def test_verification_hits_the_store_once_then_the_cache(
    service: ApiKeyService, store: FakeApiKeyStore
) -> None:
    """The ingest path must not pay a round trip per event batch."""
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="", created_by="admin")

    await service.verify(minted.plaintext)
    await service.verify(minted.plaintext)
    await service.verify(minted.plaintext)

    assert store.reads == 1


async def test_a_key_from_another_user_reads_as_missing(service: ApiKeyService) -> None:
    """So the management endpoints cannot be used to discover foreign key ids."""
    minted = await service.issue(user_uuid=USER, domain=DOMAIN, label="", created_by="admin")

    assert await service.get_for_user(minted.record.key_id, user_uuid=USER) is not None
    assert await service.get_for_user(minted.record.key_id, user_uuid="user-b") is None
