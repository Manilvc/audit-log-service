"""PII encryption and crypto-shredding.

The property under test is the one that makes the whole design lawful: erasure
must destroy the personal data while leaving the audit record - and its hash -
intact and verifiable.
"""

from __future__ import annotations

import pytest

from app.core.integrity import GENESIS_HASH, compute_hash, verify_chain
from app.core.security.crypto import (
    CIPHERTEXT_FIELD,
    KeyRingError,
    KeyShreddedError,
    PiiCipher,
)
from tests.conftest import InMemoryKeyRing

TENANT = "tenant-a"
SUBJECT = "u-42"


def _document() -> dict:
    return {
        "@timestamp": "2026-08-27T10:00:00+00:00",
        "event": {"id": "evt-1", "action": "user.login", "outcome": "success"},
        "tenant": {"id": TENANT},
        "actor": {
            "id": SUBJECT,
            "type": "user",
            "email": "alice@example.com",
            "name": "Alice Example",
        },
        "source": {"ip": "203.0.113.42", "country_code": "IN"},
        "message": "Alice Example logged in from Ahmedabad",
    }


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------
async def test_pii_is_removed_from_indexed_fields_and_moved_to_ciphertext(
    cipher: PiiCipher,
) -> None:
    """PII must not remain anywhere an index could reach it."""
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    document = result.document

    assert "email" not in document["actor"]
    assert "name" not in document["actor"]
    assert "ip" not in document.get("source", {})
    assert "message" not in document

    ciphertexts = document[CIPHERTEXT_FIELD]
    assert set(ciphertexts) == {
        "actor.email",
        "actor.name",
        "source.ip",
        "message",
    }
    # No plaintext survives anywhere in the serialised document.
    serialised = str(document)
    assert "alice@example.com" not in serialised
    assert "Alice Example" not in serialised
    assert "203.0.113.42" not in serialised


async def test_non_pii_fields_are_untouched(cipher: PiiCipher) -> None:
    """The structural evidence an auditor needs stays queryable."""
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    document = result.document
    assert document["event"]["action"] == "user.login"
    assert document["event"]["outcome"] == "success"
    assert document["actor"]["id"] == SUBJECT
    assert document["tenant"]["id"] == TENANT
    assert document["source"]["country_code"] == "IN"


async def test_ip_is_truncated_to_a_network_prefix_in_the_clear(
    cipher: PiiCipher,
) -> None:
    """Minimisation: keep the network signal, drop the identifying address."""
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    assert result.document["source"]["ip_prefix"] == "203.0.113.0/24"


async def test_ipv6_is_truncated_to_a_48_prefix(cipher: PiiCipher) -> None:
    document = _document()
    document["source"]["ip"] = "2001:db8:1234:5678::1"
    result = await cipher.encrypt_document(
        document, tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    assert result.document["source"]["ip_prefix"] == "2001:db8:1234::/48"


async def test_round_trip_restores_the_original_values(cipher: PiiCipher) -> None:
    original = _document()
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    result.document["pii"] = {"key_id": result.key_id}

    restored = await cipher.decrypt_document(result.document, event_id="evt-1")
    assert restored["actor"]["email"] == original["actor"]["email"]
    assert restored["actor"]["name"] == original["actor"]["name"]
    assert restored["source"]["ip"] == original["source"]["ip"]
    assert restored["message"] == original["message"]
    assert CIPHERTEXT_FIELD not in restored


async def test_no_encryption_when_there_is_no_data_subject(cipher: PiiCipher) -> None:
    """A system event with no identifiable person needs no key.

    Encrypting under no subject would create a key nobody could ever shred.
    """
    document = {
        "event": {"id": "evt-2", "action": "session.idle_expired"},
        "tenant": {"id": TENANT},
    }
    result = await cipher.encrypt_document(
        document, tenant_id=TENANT, event_id="evt-2", subject_id=None
    )
    assert result.key_id is None
    assert CIPHERTEXT_FIELD not in result.document


# ---------------------------------------------------------------------------
# Key identity
# ---------------------------------------------------------------------------
def test_key_id_is_deterministic_per_subject(cipher: PiiCipher) -> None:
    """All events about one subject share a key, so one erasure covers them."""
    assert cipher.subject_key_id(TENANT, SUBJECT) == cipher.subject_key_id(TENANT, SUBJECT)


def test_key_id_is_tenant_scoped(cipher: PiiCipher) -> None:
    """Identical subject ids in two tenants must never share a key.

    Otherwise erasing a subject in one tenant would destroy another tenant's
    audit data.
    """
    assert cipher.subject_key_id("tenant-a", SUBJECT) != cipher.subject_key_id("tenant-b", SUBJECT)


def test_key_id_does_not_leak_the_subject_id(cipher: PiiCipher) -> None:
    """A keyed HMAC, so reading the keyring index does not enumerate users."""
    key_id = cipher.subject_key_id(TENANT, "alice@example.com")
    assert "alice" not in key_id
    assert "example.com" not in key_id


# ---------------------------------------------------------------------------
# AAD binding
# ---------------------------------------------------------------------------
async def test_ciphertext_cannot_be_moved_between_fields(cipher: PiiCipher) -> None:
    """AAD binds a ciphertext to its field path.

    Without this, an attacker could swap `actor.email` and `actor.name`
    ciphertexts, or move a value into a field with different access rules.
    """
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    document = result.document
    document["pii"] = {"key_id": result.key_id}
    ciphertexts = document[CIPHERTEXT_FIELD]
    ciphertexts["actor.name"] = ciphertexts["actor.email"]

    restored = await cipher.decrypt_document(document, event_id="evt-1")
    assert restored["actor"]["name"] == "[UNDECRYPTABLE]"


async def test_ciphertext_cannot_be_moved_between_events(cipher: PiiCipher) -> None:
    """AAD binds a ciphertext to its event id."""
    first = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    document = first.document
    document["pii"] = {"key_id": first.key_id}

    # Same key, but the document is replayed under a different event id.
    restored = await cipher.decrypt_document(document, event_id="evt-999")
    assert restored["actor"]["email"] == "[UNDECRYPTABLE]"


async def test_one_corrupt_field_does_not_sink_the_document(
    cipher: PiiCipher,
) -> None:
    """The remaining fields are still valid evidence."""
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    document = result.document
    document["pii"] = {"key_id": result.key_id}
    document[CIPHERTEXT_FIELD]["actor.email"] = "v1:bogus:bogus"

    restored = await cipher.decrypt_document(document, event_id="evt-1")
    assert restored["actor"]["email"] == "[UNDECRYPTABLE]"
    assert restored["actor"]["name"] == "Alice Example"


# ---------------------------------------------------------------------------
# Shredding - the central guarantee
# ---------------------------------------------------------------------------
async def test_shredding_makes_pii_unrecoverable_but_keeps_the_record(
    cipher: PiiCipher, keyring: InMemoryKeyRing
) -> None:
    """The whole design in one test.

    After erasure the personal data is gone forever, while the event - who did
    what, when, with what outcome - survives as audit evidence.
    """
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    document = result.document
    document["pii"] = {"key_id": result.key_id}

    key_id, destroyed = await cipher.shred_subject(TENANT, SUBJECT)
    assert destroyed is True
    assert key_id == result.key_id
    assert key_id not in keyring.keys

    revealed = await cipher.decrypt_document(document, event_id="evt-1")

    # PII: permanently unreadable, and marked as erased rather than as absent.
    assert revealed["actor"]["email"] == "[ERASED]"
    assert revealed["message"] == "[ERASED]"
    # Evidence: fully intact.
    assert revealed["event"]["action"] == "user.login"
    assert revealed["event"]["outcome"] == "success"
    assert revealed["actor"]["id"] == SUBJECT
    assert revealed["source"]["country_code"] == "IN"
    assert revealed["source"]["ip_prefix"] == "203.0.113.0/24"


async def test_shredding_does_not_break_the_hash_chain(cipher: PiiCipher) -> None:
    """The reason the hash is computed over ciphertext.

    Verification must still succeed years after an erasure - otherwise honouring
    a DSR would destroy the tamper evidence for every other record in the chain.
    """
    chain_id = "tenant-a:0"
    documents = []
    prev = GENESIS_HASH
    for seq in range(3):
        result = await cipher.encrypt_document(
            _document(), tenant_id=TENANT, event_id=f"evt-{seq}", subject_id=SUBJECT
        )
        document = result.document
        document["event"]["id"] = f"evt-{seq}"
        document["pii"] = {
            "encrypted": True,
            "key_id": result.key_id,
            "kek_version": 1,
            "fields": list(result.encrypted_paths),
            "shredded": False,
        }
        digest = compute_hash(chain_id, seq, prev, document)
        document["integrity"] = {
            "seq": seq,
            "prev_hash": prev,
            "hash": digest,
            "algo": "sha256",
            "chain_id": chain_id,
        }
        prev = digest
        documents.append(document)

    assert verify_chain(chain_id, documents, expect_contiguous_from=0).intact

    await cipher.shred_subject(TENANT, SUBJECT)

    # The stored bytes are untouched by shredding, so the chain still verifies.
    assert verify_chain(chain_id, documents, expect_contiguous_from=0).intact


async def test_repeated_erasure_is_idempotent(cipher: PiiCipher) -> None:
    """A resubmitted DSR must not be an error."""
    await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    _, first = await cipher.shred_subject(TENANT, SUBJECT)
    _, second = await cipher.shred_subject(TENANT, SUBJECT)
    assert first is True
    assert second is False


async def test_shredded_key_cannot_be_recreated_for_new_writes(
    cipher: PiiCipher,
) -> None:
    """A shredded subject's key must not silently regenerate.

    If it did, a later event would create a fresh key under the same key id and
    the erasure would be quietly undone for all subsequent records.
    """
    await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    await cipher.shred_subject(TENANT, SUBJECT)

    with pytest.raises(KeyShreddedError):
        await cipher.encrypt_document(
            _document(), tenant_id=TENANT, event_id="evt-2", subject_id=SUBJECT
        )


async def test_other_subjects_are_unaffected_by_an_erasure(
    cipher: PiiCipher,
) -> None:
    """Erasure is surgical: one subject, not a blast radius."""
    alice = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id="u-42"
    )
    bob_doc = _document()
    bob_doc["actor"]["id"] = "u-99"
    bob_doc["actor"]["email"] = "bob@example.com"
    bob = await cipher.encrypt_document(
        bob_doc, tenant_id=TENANT, event_id="evt-2", subject_id="u-99"
    )
    bob.document["pii"] = {"key_id": bob.key_id}
    alice.document["pii"] = {"key_id": alice.key_id}

    await cipher.shred_subject(TENANT, "u-42")

    assert (await cipher.decrypt_document(alice.document, event_id="evt-1"))["actor"][
        "email"
    ] == "[ERASED]"
    assert (await cipher.decrypt_document(bob.document, event_id="evt-2"))["actor"][
        "email"
    ] == "bob@example.com"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------
def test_generated_kek_is_accepted_and_correctly_sized() -> None:
    kek = PiiCipher.generate_master_kek()
    cipher = PiiCipher(kek, keyring=InMemoryKeyRing())
    assert cipher.enabled


@pytest.mark.parametrize("bad", ["", "too-short", "!!!not-base64!!!", "A" * 10])
def test_malformed_kek_is_rejected_at_construction(bad: str) -> None:
    """Fail at startup, not on the first event.

    A bad KEK discovered mid-flight would mean rejected audit writes under load.
    """
    with pytest.raises(ValueError):
        PiiCipher(bad, keyring=InMemoryKeyRing())


async def test_wrong_kek_cannot_unwrap_an_existing_key() -> None:
    """A rotated-away or wrong KEK surfaces as a typed error, not garbage."""
    keyring = InMemoryKeyRing()
    original = PiiCipher(PiiCipher.generate_master_kek(), keyring=keyring)
    result = await original.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )

    impostor = PiiCipher(PiiCipher.generate_master_kek(), keyring=keyring)
    with pytest.raises(KeyRingError, match="wrong PII_MASTER_KEK"):
        await impostor._resolve_dek(str(result.key_id), create=False)


async def test_disabled_cipher_is_a_pass_through() -> None:
    """For a deployment with no personal data in scope."""
    cipher = PiiCipher("", keyring=InMemoryKeyRing(), enabled=False)
    result = await cipher.encrypt_document(
        _document(), tenant_id=TENANT, event_id="evt-1", subject_id=SUBJECT
    )
    assert result.key_id is None
    assert result.document["actor"]["email"] == "alice@example.com"
