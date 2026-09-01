"""The canonical audit event.

One model, one shape, for every emitter on the platform. Emitters post the
loose `AuditEventIn` wire form (see `app.schemas.ingest`); this module holds the
normalised internal representation and the exact document written to
Elasticsearch and to the WORM archive.

Two invariants make the rest of the service work:

1. **The stored document is the hashed document.** The integrity hash is
   computed over the document *after* PII encryption, never before. That is
   what lets a crypto-shred destroy personal data years later without
   invalidating the hash chain - the ciphertext bytes stay in place, only the
   key needed to read them is destroyed.
2. **`tenant.id` is never optional.** A document with no tenant cannot be
   filtered safely, so it is rejected at ingest rather than written to a
   quarantine nobody reads.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.domain.enums import (
    ActorType,
    EntityType,
    EventCategory,
    EventType,
    Outcome,
    Severity,
)

# ---------------------------------------------------------------------------
# Field-level constraints
# ---------------------------------------------------------------------------
# Bounded strings everywhere. An unbounded `keyword` field is a mapping-
# explosion and a memory risk: Lucene indexes the whole term, so a caller
# posting a 2 MB "action" would bloat every segment it lands in.
Keyword = Annotated[str, StringConstraints(min_length=1, max_length=256, strip_whitespace=True)]
ShortText = Annotated[str, StringConstraints(max_length=1024, strip_whitespace=True)]
LongText = Annotated[str, StringConstraints(max_length=8192)]
Uuid36 = Annotated[str, StringConstraints(min_length=1, max_length=64, strip_whitespace=True)]

#: Fields carrying personal data, addressed by their dotted path in the stored
#: document. This registry is the single source of truth for three subsystems:
#: crypto-shredding (`services.erasure_service`), the encrypt-on-write step
#: (`core.security.crypto`) and field-level redaction on read
#: (`services.query_service`). Adding a PII field anywhere means adding it here.
PII_FIELD_PATHS: Final[frozenset[str]] = frozenset(
    {
        "actor.email",
        "actor.name",
        "actor.phone",
        "source.ip",
        "source.user_agent",
        "target.name",
        "target.email",
        "change.before",
        "change.after",
        "message",
    }
)

#: Header/body keys that must never be persisted, in any casing. Checked when
#: flattening `http.request` metadata and arbitrary `labels`.
REDACT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "password",
        "new_password",
        "old_password",
        "current_password",
        "confirm_password",
        "secret",
        "client_secret",
        "private_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "otp",
        "pin",
        "cvv",
        "card_number",
        "aadhaar",
        "aadhaar_number",
        "pan",
        "pan_number",
        "ssn",
        "seed",
        "mnemonic",
        "signing_key",
        "kek",
        "dek",
    }
)

REDACTED_PLACEHOLDER: Final[str] = "[REDACTED]"


class Actor(BaseModel):
    """Who did it."""

    model_config = ConfigDict(extra="forbid")

    type: ActorType = ActorType.USER
    id: Uuid36 | None = None
    """Stable identifier - user UUID, service name, or None for anonymous."""
    numeric_id: int | None = None
    """Legacy integer PK from the main backend, kept for joins during migration."""
    email: ShortText | None = None
    name: ShortText | None = None
    phone: ShortText | None = None
    user_type: Keyword | None = None
    """Platform role label, e.g. ADMIN / ISSUER / HOLDER."""
    session_id: Uuid36 | None = None
    """`sid` claim - lets an investigator pivot to the whole session."""
    on_behalf_of: Uuid36 | None = None
    """Set when an admin acts as another user (impersonation)."""
    service: Keyword | None = None
    """Emitting service name for machine actors, e.g. everycred-backend."""


class Target(BaseModel):
    """What was acted upon."""

    model_config = ConfigDict(extra="forbid")

    type: EntityType = EntityType.UNKNOWN
    id: Uuid36 | None = None
    numeric_id: int | None = None
    name: ShortText | None = None
    email: ShortText | None = None
    ids: list[Uuid36] = Field(default_factory=list, max_length=1000)
    """Affected identifiers for a `.bulk` action. Capped: a genuinely larger
    batch should emit a summary event plus per-item events, not one giant doc."""
    count: int | None = Field(default=None, ge=0)
    """Total affected count, which may exceed `len(ids)` when truncated."""


class Source(BaseModel):
    """Network origin of the request."""

    model_config = ConfigDict(extra="forbid")

    ip: ShortText | None = None
    country_code: Annotated[str, StringConstraints(max_length=4)] | None = None
    city: ShortText | None = None
    user_agent: ShortText | None = None
    device_type: Keyword | None = None
    forwarded_for: ShortText | None = None


class HttpContext(BaseModel):
    """Request/response envelope, for correlating an event with an access log."""

    model_config = ConfigDict(extra="forbid")

    method: Annotated[str, StringConstraints(max_length=10)] | None = None
    path: ShortText | None = None
    status_code: int | None = Field(default=None, ge=100, le=599)
    duration_ms: float | None = Field(default=None, ge=0)
    request_id: Uuid36 | None = None
    trace_id: Uuid36 | None = None


class Change(BaseModel):
    """Before/after diff for mutations.

    Values are already-redacted, JSON-serialisable dicts. Stored as
    `flattened` in Elasticsearch so arbitrary business fields never explode
    the mapping (see `search.mappings`).
    """

    model_config = ConfigDict(extra="forbid")

    fields: list[Keyword] = Field(default_factory=list, max_length=200)
    """Names of the fields that changed - cheap to aggregate on."""
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)


class Integrity(BaseModel):
    """Tamper-evidence metadata, assigned by the writer, never by the emitter.

    `seq` and `prev_hash` are allocated inside a single Redis Lua transaction
    per (tenant, partition) chain, so the ordering is total and gap-free. A
    verifier can therefore detect deletion (missing seq), reordering (broken
    prev link) and mutation (hash mismatch).
    """

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0)
    prev_hash: str
    hash: str
    algo: str = "sha256"
    chain_id: str
    """`<tenant_id>:<partition>` - the chain this sequence belongs to."""


class PiiEnvelope(BaseModel):
    """Pointer to the key material protecting this document's PII.

    The ciphertext lives inline in the PII fields; the wrapped data key lives
    in the keyring. Erasure deletes the keyring entry, which is what makes the
    inline ciphertext permanently unreadable.
    """

    model_config = ConfigDict(extra="forbid")

    encrypted: bool = False
    key_id: str | None = None
    """Keyring identifier, derived from the data subject - see crypto.subject_key_id."""
    kek_version: int | None = None
    fields: list[str] = Field(default_factory=list)
    """Which paths in this document are ciphertext, for correct decryption."""
    shredded: bool = False
    shredded_at: datetime | None = None


class AuditEvent(BaseModel):
    """The normalised event. Serialises directly to the Elasticsearch document.

    `extra="forbid"` is intentional: a typo in an emitter's payload should be a
    422 at the boundary, not a silently-dropped field discovered during an
    incident six months later.
    """

    model_config = ConfigDict(extra="forbid", ser_json_timedelta="float")

    # ------------------------------------------------------------- identity
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    """Server-assigned unless the emitter supplies an idempotency key."""
    timestamp: datetime
    """Occurrence time, supplied by the emitter. Maps to ECS `@timestamp`."""
    ingested_at: datetime | None = None
    """Server receipt time. A large gap from `timestamp` is itself a signal."""

    # --------------------------------------------------------------- tenancy
    tenant_id: Uuid36
    """Never optional - the entire isolation model rests on this field."""
    tenant_name: ShortText | None = None
    issuer_id: Uuid36 | None = None
    """Sub-tenant scope inside a tenant, mirroring `user_audit_log.issuer_uuid`."""

    # ------------------------------------------------------------ what/where
    action: Keyword
    category: EventCategory
    type: EventType = EventType.INFO
    outcome: Outcome = Outcome.SUCCESS
    severity: Severity = Severity.INFO
    message: LongText | None = None
    """Human-readable summary. PII-bearing, so it is encrypted like other PII."""
    reason: ShortText | None = None
    """Failure detail - denial reason, validation error, exception class."""

    actor: Actor = Field(default_factory=Actor)
    target: Target = Field(default_factory=Target)
    source: Source = Field(default_factory=Source)
    http: HttpContext = Field(default_factory=HttpContext)
    change: Change = Field(default_factory=Change)

    service_name: Keyword = "unknown"
    """Which microservice emitted this event."""
    service_version: Keyword | None = None
    labels: dict[str, Any] = Field(default_factory=dict)
    """Free-form emitter context. `flattened` in ES; redacted on the way in."""

    # -------------------------------------------------- writer-assigned only
    integrity: Integrity | None = None
    pii: PiiEnvelope = Field(default_factory=PiiEnvelope)

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _require_timezone(cls, value: datetime | None) -> datetime | None:
        """Reject naive datetimes.

        A naive timestamp in an audit trail is unusable evidence: two events an
        hour apart can appear simultaneous once services run in different
        regions. Callers must send an offset.
        """
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware (include a UTC offset)")
        return value

    # ------------------------------------------------------------ ES mapping
    def to_document(self) -> dict[str, Any]:
        """Render the ECS-shaped Elasticsearch document.

        Empty containers are omitted rather than written as `{}`/`[]`: sparse
        docs compress better and keep `_source` retrieval cheap at six-year
        scale.
        """
        doc: dict[str, Any] = {
            "@timestamp": self.timestamp.isoformat(),
            "event": {
                "id": self.event_id,
                "action": self.action,
                "category": self.category.value,
                "type": self.type.value,
                "outcome": self.outcome.value,
                "severity": self.severity.value,
                "ingested": (self.ingested_at.isoformat() if self.ingested_at else None),
                "reason": self.reason,
            },
            "tenant": {
                "id": self.tenant_id,
                "name": self.tenant_name,
                "issuer_id": self.issuer_id,
            },
            "service": {"name": self.service_name, "version": self.service_version},
            "message": self.message,
        }

        actor = _prune(self.actor.model_dump(mode="json", exclude_none=True))
        if actor:
            doc["actor"] = actor
        target = _prune(self.target.model_dump(mode="json", exclude_none=True))
        if target:
            doc["target"] = target
        source = _prune(self.source.model_dump(mode="json", exclude_none=True))
        if source:
            doc["source"] = source
        http = _prune(self.http.model_dump(mode="json", exclude_none=True))
        if http:
            doc["http"] = http
        change = _prune(self.change.model_dump(mode="json", exclude_none=True))
        if change:
            doc["change"] = change
        if self.labels:
            doc["labels"] = self.labels
        if self.integrity is not None:
            doc["integrity"] = self.integrity.model_dump(mode="json")
        if self.pii.encrypted or self.pii.shredded:
            doc["pii"] = self.pii.model_dump(mode="json", exclude_none=True)

        return _prune(doc)


def _prune(value: dict[str, Any]) -> dict[str, Any]:
    """Drop keys whose value is None or an empty dict/list, recursively.

    Enum members are already coerced by `model_dump(mode="json")`; this only
    removes emptiness so it is safe to call on nested output.
    """
    cleaned: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, dict):
            nested = _prune(item)
            if nested:
                cleaned[key] = nested
        elif item is None or item == [] or item == {}:
            continue
        else:
            cleaned[key] = item
    return cleaned
