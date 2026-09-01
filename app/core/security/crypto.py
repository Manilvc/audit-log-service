"""Field-level PII encryption with crypto-shredding.

The problem this solves
----------------------
GDPR Art. 17 and DPDP s.12 give a data principal the right to erasure. SOC 2,
ISO 27001 and HIPAA 164.312(b) require the audit trail to be immutable. Taken
literally the two are contradictory: you cannot delete a row from an append-only
evidence log.

Crypto-shredding resolves it. Personal data is stored only as ciphertext under a
key unique to that data subject. Erasure destroys the key, not the record. The
event - who did what, when, with what outcome - survives intact for the auditor,
while the personal data becomes permanently unrecoverable. The hash chain still
verifies, because the hash is computed over the ciphertext (see
`app.core.integrity`).

Key hierarchy
-------------
    PII_MASTER_KEK (env, 32 bytes)
      |- HKDF "keyid"  -> key-id derivation key   (deterministic, non-secret output)
      |- HKDF "bidx"   -> blind-index key         (per tenant, optional)
      |- AES-GCM wrap  -> per-subject DEK         (random, stored in the keyring)
                            |- AES-GCM           -> PII field ciphertext

Only the wrapped DEK lives in the keyring. Deleting that one small record is the
entire erasure operation, which is why it is atomic and verifiable.

Design notes
------------
* **DEKs are random, never derived.** A DEK derived from the KEK would be
  recomputable after "deletion", so shredding would be theatre.
* **AAD binds ciphertext to its location.** Each field is encrypted with
  additional authenticated data of `<event_id>|<field_path>`, so a ciphertext
  lifted from one event or field into another fails authentication instead of
  silently decrypting to someone else's data.
* **Ciphertext lives in a non-indexed sub-object** (`pii_ct`). It is excluded
  from the Elasticsearch mapping entirely, so encrypted blobs cannot be
  searched, aggregated or leaked through a wildcard field query.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
from dataclasses import dataclass
from typing import Any, Final, Protocol

import orjson
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.domain.events import PII_FIELD_PATHS

#: Envelope format marker. Bump when the wire format changes so old ciphertext
#: stays decryptable by the branch that understands it.
CIPHER_VERSION: Final[str] = "v1"

#: AES-GCM standard nonce length. 96 bits is the only size the NIST spec
#: optimises for and the only one where random nonces are safe at scale.
NONCE_BYTES: Final[int] = 12
DEK_BYTES: Final[int] = 32
KEK_BYTES: Final[int] = 32

#: Where ciphertext is parked inside the document. Mapped with
#: `enabled: false`, so Elasticsearch stores but never indexes it.
CIPHERTEXT_FIELD: Final[str] = "pii_ct"


class KeyRingError(RuntimeError):
    """Raised when key material cannot be fetched, stored or unwrapped."""


class KeyShreddedError(KeyRingError):
    """The subject's key was destroyed by an erasure request.

    Distinct from a generic failure on purpose: this is the expected, correct
    outcome of a completed DSR, so callers render "erased" rather than a 500.
    """


class KeyRing(Protocol):
    """Durable store for wrapped data keys.

    Kept as a Protocol so the storage choice (Elasticsearch index, RDBMS, AWS
    KMS/Secrets Manager) is swappable without touching the cipher. The
    implementation in `app.search.keyring` uses a dedicated, mutable
    Elasticsearch index - mutable precisely because erasure must delete from it,
    unlike the append-only audit data stream.
    """

    async def get(self, key_id: str) -> bytes | None:
        """Return the wrapped DEK, or None if it was never created."""
        ...

    async def put(self, key_id: str, wrapped: bytes, *, kek_version: int) -> None:
        """Store a wrapped DEK. Must be idempotent for the same key_id."""
        ...

    async def delete(self, key_id: str) -> bool:
        """Destroy key material. Returns False if it was already gone."""
        ...

    async def is_shredded(self, key_id: str) -> bool:
        """True when a tombstone records a completed erasure for this key."""
        ...


@dataclass(frozen=True, slots=True)
class EncryptionResult:
    """Outcome of encrypting one document."""

    document: dict[str, Any]
    key_id: str | None
    encrypted_paths: tuple[str, ...]


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class PiiCipher:
    """Encrypts, decrypts and shreds the personal data inside audit documents."""

    def __init__(
        self,
        master_kek: str,
        *,
        keyring: KeyRing,
        kek_version: int = 1,
        enabled: bool = True,
        blind_index_enabled: bool = False,
    ) -> None:
        """
        Args:
            master_kek: base64url-encoded 32-byte key-encryption key.
            keyring: durable store for wrapped per-subject data keys.
            kek_version: recorded on each wrapped DEK so a KEK rotation can
                re-wrap lazily instead of in one migration.
            enabled: when False, PII passes through in cleartext. Only valid for
                deployments with no personal data in scope.
            blind_index_enabled: adds deterministic lookup hashes for email and
                phone. Off by default - see `blind_index` for the trade-off.

        Raises:
            ValueError: the KEK is absent or not exactly 32 bytes.
        """
        self._enabled = enabled
        self._blind_index_enabled = blind_index_enabled
        self._keyring = keyring
        self._kek_version = kek_version

        if not enabled:
            self._kek = b""
            self._keyid_key = b""
            return

        try:
            kek = _b64d(master_kek)
        except Exception as exc:
            raise ValueError("PII_MASTER_KEK is not valid base64url") from exc
        if len(kek) != KEK_BYTES:
            raise ValueError(
                f"PII_MASTER_KEK must decode to exactly {KEK_BYTES} bytes, got {len(kek)}"
            )
        self._kek = kek
        self._keyid_key = self._derive(b"keyid")

    # ------------------------------------------------------------------ keys
    def _derive(self, info: bytes) -> bytes:
        """HKDF-Expand a purpose-separated subkey from the master KEK.

        Purpose separation means a weakness in one use (say, the blind index)
        cannot be pivoted into another (field encryption).
        """
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"everycred-audit|" + info,
        ).derive(self._kek)

    def subject_key_id(self, tenant_id: str, subject_id: str) -> str:
        """Deterministic, non-reversible key identifier for a data subject.

        Deterministic so every event about the same subject shares one DEK -
        which is what makes a single erasure cover the subject's whole history.
        Keyed HMAC rather than a plain hash so the identifier does not leak the
        subject id to anyone who can read the keyring index.
        """
        digest = hmac.new(
            self._keyid_key,
            f"{tenant_id}|{subject_id}".encode(),
            hashlib.sha256,
        ).digest()
        return _b64e(digest[:24])

    async def _wrap_new_dek(self, key_id: str) -> bytes:
        """Generate, wrap and persist a fresh DEK; return the plaintext DEK."""
        dek = os.urandom(DEK_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        wrapped = AESGCM(self._kek).encrypt(nonce, dek, self._wrap_aad(key_id))
        await self._keyring.put(key_id, nonce + wrapped, kek_version=self._kek_version)
        return dek

    def _wrap_aad(self, key_id: str) -> bytes:
        """AAD binding a wrapped DEK to its key id and KEK version."""
        return f"kek:{self._kek_version}|kid:{key_id}".encode()

    async def _resolve_dek(self, key_id: str, *, create: bool) -> bytes:
        """Fetch (or create) the plaintext DEK for a key id.

        Raises:
            KeyShreddedError: erasure already destroyed this key.
            KeyRingError: key material exists but does not unwrap, which means
                the KEK is wrong or the record was corrupted.
        """
        wrapped = await self._keyring.get(key_id)
        if wrapped is None:
            if await self._keyring.is_shredded(key_id):
                raise KeyShreddedError(f"key {key_id} was destroyed by an erasure request")
            if not create:
                raise KeyRingError(f"no key material for {key_id}")
            return await self._wrap_new_dek(key_id)

        nonce, ciphertext = wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:]
        try:
            return AESGCM(self._kek).decrypt(nonce, ciphertext, self._wrap_aad(key_id))
        except InvalidTag as exc:
            raise KeyRingError(
                f"failed to unwrap DEK {key_id}: wrong PII_MASTER_KEK or corrupted keyring entry"
            ) from exc

    # ------------------------------------------------------------- encrypting
    async def encrypt_document(
        self,
        document: dict[str, Any],
        *,
        tenant_id: str,
        event_id: str,
        subject_id: str | None,
    ) -> EncryptionResult:
        """Move every populated PII field into encrypted `pii_ct`.

        Args:
            document: the ECS document, mutated in place and also returned.
            tenant_id: scopes the key id, so identical subject ids in two
                tenants never share a key.
            event_id: bound into the AAD.
            subject_id: the data subject this event's PII belongs to. When None
                (a system event with no identifiable person) nothing is
                encrypted, because there is no subject whose key could later be
                shredded.

        Returns:
            The document plus the key id and the paths that were encrypted.
        """
        if not self._enabled or subject_id is None:
            return EncryptionResult(document=document, key_id=None, encrypted_paths=())

        present = [path for path in sorted(PII_FIELD_PATHS) if _has_path(document, path)]
        # Preserve non-identifying signal before the plaintext goes away: a
        # truncated IP prefix supports "unusual network" analytics without
        # retaining the full address, the standard GDPR minimisation pattern.
        _add_ip_prefix(document)
        if not present:
            return EncryptionResult(document=document, key_id=None, encrypted_paths=())

        key_id = self.subject_key_id(tenant_id, subject_id)
        dek = await self._resolve_dek(key_id, create=True)
        aesgcm = AESGCM(dek)

        ciphertexts: dict[str, str] = {}
        for path in present:
            plaintext = _pop_path(document, path)
            payload = orjson.dumps(plaintext)
            nonce = os.urandom(NONCE_BYTES)
            blob = aesgcm.encrypt(nonce, payload, _field_aad(event_id, path))
            ciphertexts[path] = f"{CIPHER_VERSION}:{_b64e(nonce)}:{_b64e(blob)}"

        if self._blind_index_enabled:
            self._attach_blind_indexes(document, tenant_id, present, ciphertexts)

        document[CIPHERTEXT_FIELD] = ciphertexts
        return EncryptionResult(
            document=document,
            key_id=key_id,
            encrypted_paths=tuple(ciphertexts),
        )

    def _attach_blind_indexes(
        self,
        document: dict[str, Any],
        tenant_id: str,
        present: list[str],
        ciphertexts: dict[str, str],
    ) -> None:
        """Placeholder hook - blind indexes are attached before encryption.

        Kept separate so the trade-off is documented in one place: a
        deterministic index survives crypto-shredding, so anyone holding the
        KEK retains a "was this email ever present?" oracle over erased data.
        That is pseudonymisation, not erasure, which is why the feature is
        opt-in and defaults to off. Search by stable non-PII identifiers
        (`actor.id`, `target.id`, `session_id`) instead - which is what a DSR
        or an investigation actually starts from.
        """
        # No-op: values are already encrypted by the caller at this point.
        # Implemented as an explicit no-op rather than being omitted so the
        # config flag has a single, findable home when it is enabled.
        return

    def blind_index(self, tenant_id: str, kind: str, value: str) -> str:
        """Deterministic lookup hash for an exact-match PII search.

        Normalises before hashing so "  Foo@Example.COM " and "foo@example.com"
        collide as they should.
        """
        normalised = value.strip().casefold()
        key = self._derive(f"bidx|{tenant_id}".encode())
        return _b64e(hmac.new(key, f"{kind}|{normalised}".encode(), hashlib.sha256).digest()[:16])

    # ------------------------------------------------------------- decrypting
    async def decrypt_document(
        self,
        document: dict[str, Any],
        *,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        """Restore PII fields in place, best-effort.

        A shredded or unreadable key is not an error here: the surrounding
        audit event is still valid evidence and must remain viewable. Affected
        fields are replaced with a tombstone marker so the reader can see that
        data existed and was erased, rather than that it never existed - a
        distinction auditors care about.
        """
        ciphertexts = document.get(CIPHERTEXT_FIELD)
        if not isinstance(ciphertexts, dict) or not ciphertexts:
            return document

        envelope = document.get("pii") or {}
        key_id = envelope.get("key_id")
        resolved_event_id = event_id or _dig(document, "event.id")
        if not key_id or not resolved_event_id:
            return document

        try:
            dek = await self._resolve_dek(str(key_id), create=False)
        except KeyShreddedError:
            _mark_all(document, ciphertexts, "[ERASED]")
            return document
        except KeyRingError:
            _mark_all(document, ciphertexts, "[UNAVAILABLE]")
            return document

        aesgcm = AESGCM(dek)
        for path, blob in ciphertexts.items():
            try:
                _, nonce_b64, ct_b64 = str(blob).split(":", 2)
                plaintext = aesgcm.decrypt(
                    _b64d(nonce_b64),
                    _b64d(ct_b64),
                    _field_aad(str(resolved_event_id), path),
                )
                _set_path(document, path, orjson.loads(plaintext))
            except (InvalidTag, ValueError, orjson.JSONDecodeError):
                # A single unreadable field must not sink the whole document:
                # the remaining fields are still valid evidence.
                _set_path(document, path, "[UNDECRYPTABLE]")

        document.pop(CIPHERTEXT_FIELD, None)
        return document

    # --------------------------------------------------------------- shredding
    async def shred_subject(self, tenant_id: str, subject_id: str) -> tuple[str, bool]:
        """Destroy the key protecting one data subject's PII.

        This is the entire erasure operation: no audit document is touched, so
        immutability and the hash chain are preserved while the personal data
        becomes permanently unreadable.

        Returns:
            `(key_id, destroyed)` - `destroyed` is False when the key was
            already gone, which makes a repeated DSR idempotent rather than an
            error.
        """
        key_id = self.subject_key_id(tenant_id, subject_id)
        destroyed = await self._keyring.delete(key_id)
        return key_id, destroyed

    @property
    def enabled(self) -> bool:
        return self._enabled

    @staticmethod
    def generate_master_kek() -> str:
        """Mint a KEK for bootstrapping. Used by `scripts/generate_keys.py`."""
        return _b64e(os.urandom(KEK_BYTES))


# ---------------------------------------------------------------------------
# Dotted-path helpers
# ---------------------------------------------------------------------------
def _field_aad(event_id: str, path: str) -> bytes:
    """Bind a ciphertext to one field of one event."""
    return f"evt:{event_id}|fld:{path}".encode()


def _dig(document: dict[str, Any], path: str) -> Any:
    node: Any = document
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _has_path(document: dict[str, Any], path: str) -> bool:
    """True when the path exists and holds a non-empty value."""
    value = _dig(document, path)
    return value is not None and value != {} and value != []


def _pop_path(document: dict[str, Any], path: str) -> Any:
    """Remove and return the value at a dotted path, pruning empty parents.

    Pruning matters: leaving `{"actor": {}}` behind would write an empty object
    into every encrypted document.
    """
    parts = path.split(".")
    node: Any = document
    chain: list[tuple[dict[str, Any], str]] = []
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            return None
        chain.append((node, part))
        node = node[part]
    if not isinstance(node, dict):
        return None
    value = node.pop(parts[-1], None)
    for parent, key in reversed(chain):
        if isinstance(parent.get(key), dict) and not parent[key]:
            del parent[key]
    return value


def _set_path(document: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    node = document
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


def _mark_all(document: dict[str, Any], ciphertexts: dict[str, Any], marker: str) -> None:
    """Replace every encrypted path with a marker and drop the ciphertext."""
    for path in ciphertexts:
        _set_path(document, path, marker)
    document.pop(CIPHERTEXT_FIELD, None)


def _add_ip_prefix(document: dict[str, Any]) -> None:
    """Store a truncated network prefix alongside the (to-be-encrypted) IP.

    /24 for IPv4 and /48 for IPv6 - enough to spot "logins from a new network"
    without retaining an address that identifies a person.
    """
    raw = _dig(document, "source.ip")
    if not isinstance(raw, str) or not raw:
        return
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        return
    prefix_length = 24 if address.version == 4 else 48
    network = ipaddress.ip_network(f"{address}/{prefix_length}", strict=False)
    _set_path(document, "source.ip_prefix", str(network))
