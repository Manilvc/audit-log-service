"""Shared test fixtures.

Populates the minimum environment variables before any settings object is
constructed, then provides reusable fakes (tenant router, cipher settings) used
by both unit and integration suites.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

# Environment must be populated before `app.core.config` is imported anywhere,
# because Settings validates at construction and the module-level app in
# app.main builds one on import.
os.environ.setdefault("ENVIRONMENT", "local")
os.environ.setdefault(
    "JWT_SECRET_KEY",
    # 32+ bytes: HS256 requires it, and Settings now enforces it at startup.
    "unit-test-signing-secret-0123456789abcdef",
)
os.environ.setdefault("JWT_AUDIENCE", "everycred-api")
os.environ.setdefault("ES_HOSTS", "http://localhost:9200")
os.environ.setdefault("ES_USERNAME", "elastic")
os.environ.setdefault("ES_PASSWORD", "test-password")
os.environ.setdefault("ARCHIVE_ENABLED", "false")
os.environ.setdefault("SERVICE_API_KEYS", "test-key-one,test-key-two")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")
# A fixed, obviously-fake KEK: deterministic tests beat a random key, and this
# value never leaves the test suite.
os.environ.setdefault("PII_MASTER_KEK", "A" * 43)

from app.core.config import Settings, get_settings
from app.core.security.crypto import KeyRing, PiiCipher
from app.search.routing import TenantRouter


@pytest.fixture
def settings() -> Settings:
    return get_settings()


@pytest.fixture
def router(settings: Settings) -> TenantRouter:
    return TenantRouter(
        shared_stream=settings.SHARED_DATA_STREAM,
        index_prefix=settings.INDEX_PREFIX,
        dedicated_tenants=frozenset({"big-tenant"}),
    )


class InMemoryKeyRing(KeyRing):
    """Keyring backed by a dict.

    Faithful to the contract that matters: `put` is create-only (so a race
    adopts the winner's key) and `delete` leaves a tombstone (so a shredded key
    is distinguishable from one that never existed).
    """

    def __init__(self) -> None:
        self.keys: dict[str, bytes] = {}
        self.tombstones: dict[str, dict[str, Any]] = {}

    async def get(self, key_id: str) -> bytes | None:
        return self.keys.get(key_id)

    async def put(self, key_id: str, wrapped: bytes, *, kek_version: int) -> None:
        self.keys.setdefault(key_id, wrapped)

    async def delete(
        self,
        key_id: str,
        *,
        reason: str = "test",
        request_id: str | None = None,
    ) -> bool:
        existed = self.keys.pop(key_id, None) is not None
        self.tombstones[key_id] = {"reason": reason, "request_id": request_id}
        return existed

    async def is_shredded(self, key_id: str) -> bool:
        return key_id in self.tombstones


@pytest.fixture
def keyring() -> InMemoryKeyRing:
    return InMemoryKeyRing()


@pytest.fixture
def cipher(keyring: InMemoryKeyRing) -> PiiCipher:
    return PiiCipher(
        PiiCipher.generate_master_kek(),
        keyring=keyring,
        kek_version=1,
        enabled=True,
    )
