"""Public API contract.

Wire models are separate from the domain model on purpose. Emitters send a
forgiving shape - timestamps default to now, category is inferred, severity is
derived - while `app.domain.events.AuditEvent` stays strict and fully
normalised. Collapsing the two would force every call site to compute fields
the service can derive itself, and every emitter to be redeployed whenever a
derivation rule changed.

Every model sets `extra="forbid"`. A silently ignored typo in an emitter's
payload is a missing audit field discovered during an incident; a 422 at deploy
time is not.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.domain.enums import (
    ActorType,
    EntityType,
    EventCategory,
    EventType,
    Outcome,
    Severity,
    infer_category,
)
from app.domain.events import (
    REDACT_KEYS,
    REDACTED_PLACEHOLDER,
    Actor,
    AuditEvent,
    Change,
    HttpContext,
    Source,
    Target,
)

Keyword = Annotated[str, StringConstraints(min_length=1, max_length=256, strip_whitespace=True)]


class AuditEventIn(BaseModel):
    """One audit event as an emitting service sends it."""

    model_config = ConfigDict(extra="forbid")

    action: Keyword
    """Dotted verb, e.g. `credential.issue`. See `app.domain.enums.Action`."""

    timestamp: datetime | None = None
    """When it happened. Defaults to receipt time, but emitters should send it:
    the gap between occurrence and ingest is itself audit-relevant."""

    tenant_id: Keyword | None = None
    """Optional here because a service principal may set it via the
    `x-audit-tenant-id` header. Exactly one of the two must be present, and the
    ingest service rejects the event when the two disagree."""

    tenant_name: str | None = Field(default=None, max_length=1024)
    issuer_id: str | None = Field(default=None, max_length=64)

    category: EventCategory | None = None
    """Inferred from the action prefix when omitted."""
    type: EventType = EventType.INFO
    outcome: Outcome = Outcome.SUCCESS
    severity: Severity | None = None
    """Derived from the action, escalated on failure, when omitted."""

    message: str | None = Field(default=None, max_length=8192)
    reason: str | None = Field(default=None, max_length=1024)

    actor: Actor | None = None
    target: Target | None = None
    source: Source | None = None
    http: HttpContext | None = None
    change: Change | None = None

    service_name: Keyword = "unknown"
    service_version: str | None = Field(default=None, max_length=64)
    labels: dict[str, Any] = Field(default_factory=dict)

    event_id: str | None = Field(default=None, max_length=64)
    """Idempotency key. Supplying a stable value makes a retry from the emitter
    safe: the ES write is keyed on it, so a duplicate is rejected."""

    @field_validator("labels")
    @classmethod
    def _redact_labels(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Strip credential-shaped keys from free-form labels.

        Emitters pass request context here, and that is exactly where an
        `authorization` header or a `password` field ends up by accident. Since
        the audit log is retained for six years and is widely readable, filtering
        at the boundary is the only reliable place to catch it.
        """
        return _redact_mapping(value, depth=0)

    @field_validator("timestamp")
    @classmethod
    def _reject_naive(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("timestamp must include a UTC offset")
        return value

    def to_domain(self, *, tenant_id: str, max_clock_skew_seconds: int | None = None) -> AuditEvent:
        """Normalise into the strict domain event.

        Args:
            tenant_id: the resolved tenant, already reconciled against the
                authenticated principal by the ingest service.
            max_clock_skew_seconds: tolerance between the emitter's claimed
                `timestamp` and receipt time before the event is marked
                clock-suspect. None disables the check.
        """
        received = datetime.now(UTC)
        occurred = self.timestamp or received
        category = self.category or infer_category(self.action)
        severity = self.severity or _derive_severity(self.action, self.outcome)

        change = self.change
        if change is not None:
            change = Change(
                fields=change.fields,
                before=_redact_mapping(change.before, depth=0),
                after=_redact_mapping(change.after, depth=0),
            )

        labels = self.labels
        if self.timestamp is not None and max_clock_skew_seconds is not None:
            skew = _clock_skew(claimed=occurred, received=received)
            if abs(skew) > max_clock_skew_seconds:
                # Annotate, never reject and never rewrite. Dropping the event
                # would destroy audit evidence over a clock problem, and
                # correcting the timestamp would replace what the emitter
                # asserted with what this service assumes - both are worse than
                # recording an event that says plainly it cannot be trusted for
                # ordering. `labels` is `flattened`, so this adds a queryable
                # marker with no mapping change:
                #   labels.clock_skew_suspect: true
                labels = {
                    **labels,
                    "clock_skew_suspect": True,
                    "clock_skew_seconds": skew,
                }

        return AuditEvent(
            event_id=self.event_id or str(_new_uuid()),
            timestamp=occurred,
            ingested_at=received,
            tenant_id=tenant_id,
            tenant_name=self.tenant_name,
            issuer_id=self.issuer_id,
            action=self.action,
            category=category,
            type=self.type,
            outcome=self.outcome,
            severity=severity,
            message=self.message,
            reason=self.reason,
            actor=self.actor or Actor(),
            target=self.target or Target(),
            source=self.source or Source(),
            http=self.http or HttpContext(),
            change=change or Change(),
            service_name=self.service_name,
            service_version=self.service_version,
            labels=labels,
        )


class IngestBatchIn(BaseModel):
    """A batch of events. Batching is strongly preferred over one call each."""

    model_config = ConfigDict(extra="forbid")

    events: list[AuditEventIn] = Field(min_length=1, max_length=500)


class IngestAccepted(BaseModel):
    """Response to an accepted ingest.

    202, not 201: the events are durably queued, not yet in Elasticsearch. The
    honest status code matters - a caller must not infer from a 201 that the
    event is immediately searchable.
    """

    accepted: int
    rejected: int
    event_ids: list[str]
    errors: list[dict[str, Any]] = Field(default_factory=list)


class SearchRequest(BaseModel):
    """Typed search criteria.

    Note what is absent: there is no field for raw Elasticsearch DSL. Accepting
    one would hand callers `script` queries, unbounded wildcards and deep
    aggregations on a cluster holding every tenant's audit trail.
    """

    model_config = ConfigDict(extra="forbid")

    start: datetime | None = None
    end: datetime | None = None

    actions: list[Keyword] = Field(default_factory=list, max_length=50)
    categories: list[EventCategory] = Field(default_factory=list, max_length=20)
    outcomes: list[Outcome] = Field(default_factory=list, max_length=3)
    severities: list[Severity] = Field(default_factory=list, max_length=5)

    actor_ids: list[Keyword] = Field(default_factory=list, max_length=50)
    actor_types: list[ActorType] = Field(default_factory=list, max_length=10)
    session_id: str | None = Field(default=None, max_length=64)

    target_ids: list[Keyword] = Field(default_factory=list, max_length=50)
    target_types: list[EntityType] = Field(default_factory=list, max_length=20)

    issuer_id: str | None = Field(default=None, max_length=64)
    service_names: list[Keyword] = Field(default_factory=list, max_length=20)
    request_id: str | None = Field(default=None, max_length=64)
    trace_id: str | None = Field(default=None, max_length=64)
    event_ids: list[Keyword] = Field(default_factory=list, max_length=50)

    ip_prefix: str | None = Field(default=None, max_length=64)
    """Truncated network prefix, e.g. `203.0.113.0/24`. Full addresses are
    encrypted and therefore not searchable by design."""
    country_codes: list[Annotated[str, StringConstraints(max_length=4)]] = Field(
        default_factory=list, max_length=20
    )

    http_status_min: int | None = Field(default=None, ge=100, le=599)
    http_status_max: int | None = Field(default=None, ge=100, le=599)

    label_terms: dict[str, str] | None = Field(default=None)
    text: str | None = Field(default=None, max_length=512)

    size: int = Field(default=50, ge=1, le=200)
    cursor: list[Any] | None = None
    """Opaque `search_after` cursor from the previous page. Deep pagination uses
    this rather than an offset, so page 500 costs the same as page 1."""
    with_total: bool = False
    """Off by default: counting every match over six years of data costs far
    more than the page itself, and is capped when requested."""
    fields: list[str] | None = Field(default=None, max_length=40)
    """Restrict `_source` to these paths, which cuts decompression cost."""

    @field_validator("label_terms")
    @classmethod
    def _bound_label_terms(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        """Cap the number of label filters.

        Each becomes a separate clause, and an unbounded set is a cheap way to
        build an expensive query.
        """
        if value is not None and len(value) > 20:
            raise ValueError("at most 20 label_terms may be supplied")
        return value


class SearchResponse(BaseModel):
    """One page of audit events."""

    events: list[dict[str, Any]]
    cursor: list[Any] | None
    """Pass back as `cursor` for the next page. None means end of results."""
    total: int | None
    """Only populated when `with_total` was requested; capped for cost."""
    took_ms: int
    partial: bool = False
    """True if the search timed out server-side, so results are incomplete -
    surfaced rather than hidden, because an incomplete compliance report that
    looks complete is worse than a visible error."""


class AggregationRequest(SearchRequest):
    """Dashboard aggregation over the same filter surface."""

    model_config = ConfigDict(extra="forbid")

    group_by: Literal[
        "event.action",
        "event.category",
        "event.outcome",
        "event.severity",
        "actor.id",
        "actor.type",
        "target.type",
        "service.name",
        "source.country_code",
        "tenant.id",
    ] = "event.action"
    """A closed allow-list. An arbitrary field name would let a caller aggregate
    on a high-cardinality keyword and exhaust cluster heap."""

    interval: Literal["1m", "5m", "1h", "6h", "1d", "7d"] | None = None
    """When set, buckets the terms aggregation over time."""
    buckets: int = Field(default=50, ge=1, le=200)


class IntegrityVerifyRequest(BaseModel):
    """Request to verify a hash chain."""

    model_config = ConfigDict(extra="forbid")

    chain_id: str | None = Field(default=None, max_length=128)
    """Verify one chain. Omit to verify every chain for the tenant."""
    start_seq: int = Field(default=0, ge=0)
    max_events: int = Field(default=10_000, ge=1, le=100_000)


class IntegrityReport(BaseModel):
    """Result of a verification run - the artefact an auditor is shown."""

    tenant_id: str
    chains_checked: int
    events_verified: int
    intact: bool
    breaks: list[dict[str, Any]]
    checkpoint: dict[str, Any] | None = None
    """The most recent WORM-notarised checkpoint, when the archive is enabled.
    This is what makes the report meaningful: without an immutable anchor, a
    self-consistent chain only proves nobody edited a single record in place."""
    verified_at: datetime


class ErasureRequest(BaseModel):
    """A data-subject erasure request (GDPR Art. 17 / DPDP s.12)."""

    model_config = ConfigDict(extra="forbid")

    subject_id: Keyword
    """The data subject's stable identifier, normally their user UUID."""
    reason: str = Field(min_length=3, max_length=512)
    """Recorded on the tombstone. Required, because an erasure with no stated
    basis is not defensible to a regulator."""
    request_reference: str | None = Field(default=None, max_length=128)
    """Ticket or DSR reference, for traceability back to the original request."""
    confirm: Literal[True]
    """Explicit confirmation. Irreversible: once the key is destroyed the
    personal data cannot be recovered by anyone, including the platform
    operator."""


class ErasureReceipt(BaseModel):
    """Proof that an erasure was carried out."""

    subject_id: str
    key_id: str
    destroyed: bool
    """False when the key was already gone, which makes a repeat request
    idempotent rather than an error."""
    affected_events: int
    """How many audit records held PII under this key - reportable under GDPR
    Art. 19."""
    erased_at: datetime
    audit_event_id: str
    """The audit event recording this erasure. The erasure is itself audited."""


class ExportRequest(SearchRequest):
    """Bulk export request. Streamed NDJSON over a point-in-time snapshot."""

    model_config = ConfigDict(extra="forbid")

    max_events: int = Field(default=100_000, ge=1, le=1_000_000)
    include_integrity: bool = True
    """Keep the integrity block so the recipient can verify the chain
    independently - which is the point of an evidence export."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _new_uuid() -> Any:
    import uuid

    return uuid.uuid4()


def _derive_severity(action: str, outcome: Outcome) -> Severity:
    from app.domain.enums import default_severity

    return default_severity(action, outcome)


def _clock_skew(*, claimed: datetime, received: datetime) -> int:
    """Signed seconds between the emitter's clock and ours.

    Positive means the emitter claims the action happened in this service's
    future, which is impossible and always indicates a wrong clock. Negative
    means the event is older than the tolerance - ordinary for a backfill, and
    suspicious for live traffic, so both directions are reported and the
    operator reads the sign.
    """
    return int((claimed - received).total_seconds())


def _redact_mapping(value: dict[str, Any], *, depth: int) -> dict[str, Any]:
    """Recursively replace sensitive keys with a placeholder.

    Depth-bounded so a hostile or accidentally cyclic payload cannot turn
    validation into a stack overflow.
    """
    if depth > 6:
        return {}
    redacted: dict[str, Any] = {}
    for key, item in value.items():
        if str(key).lower() in REDACT_KEYS:
            redacted[key] = REDACTED_PLACEHOLDER
        elif isinstance(item, dict):
            redacted[key] = _redact_mapping(item, depth=depth + 1)
        elif isinstance(item, list):
            redacted[key] = [
                _redact_mapping(entry, depth=depth + 1) if isinstance(entry, dict) else entry
                for entry in item[:100]
            ]
        else:
            redacted[key] = item
    return redacted
