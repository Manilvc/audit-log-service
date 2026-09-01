"""Elasticsearch-backed keyring for wrapped PII data keys.

Implements `app.core.security.crypto.KeyRing`. Lives in a dedicated *mutable*
index, unlike the append-only audit data stream, because erasure works by
deleting from it.

Failure semantics are asymmetric on purpose:

* A **write** failure must abort the ingest of that event. Storing ciphertext
  whose key was never persisted produces a permanently unreadable record and
  silently destroys evidence, so it is better to fail loudly and let the queue
  retry.
* A **read** failure degrades to a tombstone marker on the affected fields; the
  surrounding audit event is still valid evidence and must remain viewable.

The wrapped key is stored base64-encoded in a `keyword` field with
`index: false`, so it is never analysed, never searchable, and only ever
retrieved by document id.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from typing import Any

from elasticsearch import AsyncElasticsearch, ConflictError, NotFoundError

from app.core.logging import get_logger
from app.core.security.crypto import KeyRingError

logger = get_logger(__name__)


class ElasticKeyRing:
    """Durable store for wrapped data keys, with a small in-process cache."""

    def __init__(
        self,
        client: AsyncElasticsearch,
        *,
        index: str,
        cache_size: int = 2048,
    ) -> None:
        self._client = client
        self._index = index
        self._cache_size = cache_size
        # A cache is worth it because a single ingest batch typically carries
        # many events for the same actor, and every one of them would otherwise
        # be a separate GET. Bounded, and cleared on shred so a destroyed key
        # can never be served from memory.
        self._cache: dict[str, bytes] = {}
        self._shredded: set[str] = set()

    async def get(self, key_id: str) -> bytes | None:
        if key_id in self._shredded:
            return None
        cached = self._cache.get(key_id)
        if cached is not None:
            return cached

        try:
            response = await self._client.get(
                index=self._index,
                id=key_id,
                # Only the fields needed; skips decompressing the rest.
                source_includes=["wrapped", "shredded"],
            )
        except NotFoundError:
            return None
        except Exception as exc:
            raise KeyRingError(f"keyring read failed for {key_id}: {exc}") from exc

        source: dict[str, Any] = response.get("_source", {})
        if source.get("shredded"):
            self._shredded.add(key_id)
            return None

        wrapped = source.get("wrapped")
        if not wrapped:
            return None
        raw = base64.b64decode(wrapped)
        self._remember(key_id, raw)
        return raw

    async def put(self, key_id: str, wrapped: bytes, *, kek_version: int) -> None:
        """Persist a wrapped DEK.

        `op_type=create` makes this a no-op-on-conflict rather than an
        overwrite. Two concurrent workers can race to create the first key for a
        subject; the loser must adopt the winner's key, because overwriting
        would orphan any ciphertext the winner already wrote.
        """
        document = {
            "wrapped": base64.b64encode(wrapped).decode(),
            "kek_version": kek_version,
            "created_at": datetime.now(UTC).isoformat(),
            "shredded": False,
        }
        try:
            await self._client.index(
                index=self._index,
                id=key_id,
                document=document,
                op_type="create",
                # The very next operation reads this key back to encrypt with
                # it, so it must be immediately visible.
                refresh="wait_for",
            )
            self._remember(key_id, wrapped)
        except ConflictError:
            # Lost the race. Drop the locally generated key and let the caller
            # re-read the winning one.
            logger.info("keyring_create_conflict", key_id=key_id)
            self._cache.pop(key_id, None)
        except Exception as exc:
            raise KeyRingError(f"keyring write failed for {key_id}: {exc}") from exc

    async def delete(
        self,
        key_id: str,
        *,
        reason: str = "data_subject_request",
        request_id: str | None = None,
    ) -> bool:
        """Destroy key material, leaving a tombstone behind.

        The record is *replaced* by a tombstone rather than deleted outright.
        The tombstone is what lets a reader say "this data was erased on
        request" instead of "this data never existed" - a distinction auditors
        ask about, and evidence that the DSR was actually honoured.

        Returns:
            True if key material was destroyed now; False if it was already
            gone, which keeps a repeated DSR idempotent.
        """
        tombstone = {
            "wrapped": None,
            "shredded": True,
            "shredded_at": datetime.now(UTC).isoformat(),
            "shred_reason": reason[:512],
            "shred_request_id": request_id,
        }
        try:
            response = await self._client.update(
                index=self._index,
                id=key_id,
                doc=tombstone,
                refresh="wait_for",
            )
        except NotFoundError:
            # Never existed, or already hard-deleted. Record the tombstone so a
            # later lookup still reports "erased" rather than "unknown".
            await self._client.index(
                index=self._index,
                id=key_id,
                document={**tombstone, "kek_version": None, "created_at": None},
                refresh="wait_for",
            )
            self._forget(key_id)
            return False
        except Exception as exc:
            raise KeyRingError(f"keyring shred failed for {key_id}: {exc}") from exc

        self._forget(key_id)
        already = response.get("result") == "noop"
        logger.warning(
            "pii_key_shredded",
            key_id=key_id,
            reason=reason,
            request_id=request_id,
            newly_destroyed=not already,
        )
        return not already

    async def is_shredded(self, key_id: str) -> bool:
        if key_id in self._shredded:
            return True
        try:
            response = await self._client.get(
                index=self._index, id=key_id, source_includes=["shredded"]
            )
        except NotFoundError:
            return False
        except Exception:
            return False
        shredded = bool(response.get("_source", {}).get("shredded"))
        if shredded:
            self._shredded.add(key_id)
        return shredded

    # ------------------------------------------------------------------ cache
    def _remember(self, key_id: str, wrapped: bytes) -> None:
        if len(self._cache) >= self._cache_size:
            # Plain FIFO eviction: an LRU is not worth the bookkeeping when the
            # access pattern is "hot for one batch, then cold forever".
            self._cache.pop(next(iter(self._cache)), None)
        self._cache[key_id] = wrapped

    def _forget(self, key_id: str) -> None:
        """Evict a destroyed key so it can never be served from memory."""
        self._cache.pop(key_id, None)
        self._shredded.add(key_id)
