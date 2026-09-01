"""Ingest path: tenant resolution, redaction and event normalisation.

Tenant resolution is the security-critical half. If a service key could write
into an arbitrary tenant's trail, the result is *forged* evidence, which is worse
than missing evidence: it looks authentic and it verifies.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.exceptions import IngestRejected
from app.core.security.auth import AuthorizationError, Principal
from app.domain.enums import (
    Action,
    ActorType,
    EventCategory,
    Outcome,
    Scope,
    Severity,
    default_severity,
    infer_category,
)
from app.domain.events import REDACTED_PLACEHOLDER, Actor, AuditEvent, Change, Source
from app.schemas.api import AuditEventIn, IngestBatchIn
from app.search.routing import TenantRouter
from app.services.ingest_service import IngestService


class FakeQueue:
    """Captures what would have been enqueued."""

    def __init__(self) -> None:
        self.published: list[tuple[int, dict[str, Any]]] = []

    async def publish_many(self, items: list[tuple[int, dict[str, Any]]]) -> list[str]:
        self.published.extend(items)
        return [f"id-{index}" for index in range(len(items))]

    async def publish(self, partition: int, payload: dict[str, Any]) -> str:
        self.published.append((partition, payload))
        return "id-0"


@pytest.fixture
def queue() -> FakeQueue:
    return FakeQueue()


@pytest.fixture
def ingest(settings: Settings, queue: FakeQueue, router: TenantRouter) -> IngestService:
    return IngestService(settings=settings, queue=queue, router=router)  # type: ignore[arg-type]


def _service_principal(tenant_id: str | None = None) -> Principal:
    return Principal(
        subject="everycred-backend",
        actor_type=ActorType.SERVICE,
        tenant_id=tenant_id,
        scopes=frozenset({Scope.WRITE, Scope.READ}),
    )


def _user_principal(tenant_id: str | None = "tenant-a") -> Principal:
    return Principal(
        subject="u-42",
        actor_type=ActorType.USER,
        tenant_id=tenant_id,
        scopes=frozenset({Scope.WRITE, Scope.READ}),
    )


def _event(**overrides: Any) -> AuditEventIn:
    payload: dict[str, Any] = {"action": "credential.issue"}
    payload.update(overrides)
    return AuditEventIn(**payload)


# ---------------------------------------------------------------------------
# Tenant resolution
# ---------------------------------------------------------------------------
async def test_service_uses_the_tenant_header(ingest: IngestService, queue: FakeQueue) -> None:
    result = await ingest.ingest(
        [_event()], principal=_service_principal(), header_tenant_id="tenant-a"
    )
    assert result.accepted == 1
    assert queue.published[0][1]["tenant_id"] == "tenant-a"


async def test_user_token_tenant_claim_wins_over_any_header(
    ingest: IngestService, queue: FakeQueue
) -> None:
    """A user token can never be redirected at another tenant.

    Even a header naming a different tenant is ignored, because a user's tenant
    is fixed by their token.
    """
    result = await ingest.ingest(
        [_event()],
        principal=_user_principal("tenant-a"),
        header_tenant_id="tenant-b",
    )
    assert result.accepted == 1
    assert queue.published[0][1]["tenant_id"] == "tenant-a"


async def test_body_tenant_contradicting_the_principal_is_rejected(
    ingest: IngestService,
) -> None:
    """A body-supplied tenant may confirm, never widen."""
    result = await ingest.ingest(
        [_event(tenant_id="tenant-evil")],
        principal=_service_principal(),
        header_tenant_id="tenant-a",
    )
    assert result.accepted == 0
    assert result.rejected == 1
    assert "does not match the authenticated tenant" in result.errors[0]["reason"]


async def test_body_tenant_matching_the_principal_is_accepted(
    ingest: IngestService,
) -> None:
    result = await ingest.ingest(
        [_event(tenant_id="tenant-a")],
        principal=_service_principal(),
        header_tenant_id="tenant-a",
    )
    assert result.accepted == 1


async def test_no_resolvable_tenant_is_rejected(ingest: IngestService) -> None:
    result = await ingest.ingest([_event()], principal=_service_principal(), header_tenant_id=None)
    assert result.rejected == 1
    assert "cannot determine the tenant" in result.errors[0]["reason"]


async def test_hostile_tenant_id_is_rejected(ingest: IngestService) -> None:
    """A tenant id becomes part of an index name, so it is validated."""
    result = await ingest.ingest(
        [_event()], principal=_service_principal(), header_tenant_id="audit-*"
    )
    assert result.accepted == 0
    assert result.rejected == 1


async def test_write_scope_is_required(ingest: IngestService) -> None:
    reader = Principal(
        subject="u-42",
        actor_type=ActorType.USER,
        tenant_id="tenant-a",
        scopes=frozenset({Scope.READ}),
    )
    with pytest.raises(AuthorizationError, match="audit:write"):
        await ingest.ingest([_event()], principal=reader, header_tenant_id="tenant-a")


async def test_oversized_batch_is_rejected(ingest: IngestService, settings: Settings) -> None:
    events = [_event() for _ in range(settings.MAX_INGEST_BATCH_SIZE + 1)]
    with pytest.raises(IngestRejected, match="exceeds the maximum"):
        await ingest.ingest(events, principal=_service_principal(), header_tenant_id="tenant-a")


# ---------------------------------------------------------------------------
# Partial success
# ---------------------------------------------------------------------------
async def test_one_bad_event_does_not_reject_the_batch(
    ingest: IngestService, queue: FakeQueue
) -> None:
    """499 valid events must not be discarded because of one bad neighbour."""
    events = [_event(), _event(tenant_id="tenant-evil"), _event()]
    result = await ingest.ingest(
        events, principal=_service_principal(), header_tenant_id="tenant-a"
    )
    assert result.accepted == 2
    assert result.rejected == 1
    assert result.errors[0]["index"] == 1  # the caller learns which one failed
    assert len(queue.published) == 2


async def test_a_tenant_always_lands_on_one_partition(
    ingest: IngestService, queue: FakeQueue
) -> None:
    """Chain ordering depends on this: one tenant, one partition."""
    await ingest.ingest(
        [_event() for _ in range(5)],
        principal=_service_principal(),
        header_tenant_id="tenant-a",
    )
    assert len({partition for partition, _ in queue.published}) == 1


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "key",
    [
        "authorization",
        "Authorization",
        "cookie",
        "x-api-key",
        "password",
        "new_password",
        "access_token",
        "refresh_token",
        "otp",
        "aadhaar_number",
        "pan",
        "cvv",
        "private_key",
        "client_secret",
        "mnemonic",
    ],
)
def test_credential_shaped_labels_are_redacted(key: str) -> None:
    """Emitters pass request context in `labels`, which is exactly where an
    Authorization header or a password ends up by accident.

    The audit log is retained for six years and widely readable, so filtering at
    the boundary is the only reliable place to catch it.
    """
    event = AuditEventIn(action="user.login", labels={key: "super-secret-value"})
    assert event.labels[key] == REDACTED_PLACEHOLDER


def test_redaction_reaches_nested_labels() -> None:
    event = AuditEventIn(
        action="user.login",
        labels={"request": {"headers": {"authorization": "Bearer abc"}}},
    )
    assert event.labels["request"]["headers"]["authorization"] == REDACTED_PLACEHOLDER


def test_redaction_preserves_harmless_labels() -> None:
    event = AuditEventIn(action="user.login", labels={"batch_id": "b-77", "retry_count": 3})
    assert event.labels == {"batch_id": "b-77", "retry_count": 3}


def test_change_diffs_are_redacted() -> None:
    """A before/after diff on a user record can carry a password hash."""
    event = AuditEventIn(
        action="user.profile_update",
        change=Change(
            fields=["password", "email"],
            before={"password": "old-hash", "email": "a@b.c"},
            after={"password": "new-hash", "email": "x@y.z"},
        ),
    )
    domain = event.to_domain(tenant_id="tenant-a")
    assert domain.change.before["password"] == REDACTED_PLACEHOLDER
    assert domain.change.after["password"] == REDACTED_PLACEHOLDER
    # The field *names* survive: knowing the password changed is audit-relevant.
    assert "password" in domain.change.fields
    assert domain.change.before["email"] == "a@b.c"


def test_redaction_is_depth_bounded() -> None:
    """A pathologically nested payload must not blow the stack."""
    nested: dict[str, Any] = {"password": "leak"}
    for _ in range(50):
        nested = {"level": nested}
    event = AuditEventIn(action="user.login", labels=nested)
    assert event.labels is not None  # validation completed rather than recursing


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def test_category_is_inferred_from_the_action() -> None:
    event = AuditEventIn(action="credential.revoke")
    assert event.to_domain(tenant_id="t").category is EventCategory.CREDENTIAL


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("user.login", EventCategory.AUTHENTICATION),
        ("session.created", EventCategory.SESSION),
        ("role.update", EventCategory.IAM),
        ("holder.login", EventCategory.AUTHENTICATION),
        ("holder.kyc_validate", EventCategory.IAM),
        ("webhook.send", EventCategory.INTEGRATION),
        ("audit_log.search", EventCategory.AUDIT),
        ("record.create", EventCategory.RECORD),
        ("consent.withdraw", EventCategory.CONSENT),
    ],
)
def test_category_inference_prefers_the_longest_prefix(
    action: str, expected: EventCategory
) -> None:
    """`holder.login` must resolve as authentication, not the generic `holder.`.

    Ordering matters, which is why the prefix table is an ordered tuple.
    """
    assert infer_category(action) is expected


def test_severity_escalates_on_failure() -> None:
    """A failed privileged operation is what an intrusion attempt looks like."""
    assert default_severity(Action.PERMISSION_GRANT.value, Outcome.SUCCESS) is Severity.HIGH
    assert default_severity(Action.PERMISSION_GRANT.value, Outcome.FAILURE) is Severity.CRITICAL


def test_severity_of_an_unknown_action_does_not_raise() -> None:
    """An emitter may ship an action ahead of this service's enum."""
    assert default_severity("something.brand_new", Outcome.SUCCESS) is Severity.INFO


def test_severity_never_escalates_past_critical() -> None:
    assert default_severity(Action.TENANT_SUSPEND.value, Outcome.FAILURE) is Severity.CRITICAL


def test_naive_timestamp_is_rejected() -> None:
    """Two events an hour apart must not look simultaneous across regions."""
    with pytest.raises(ValidationError, match="UTC offset"):
        AuditEventIn(action="user.login", timestamp=datetime(2026, 8, 27, 10, 0))


def test_unknown_top_level_field_is_rejected() -> None:
    """A typo must be a 422 now, not a missing field discovered in an incident."""
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AuditEventIn(action="user.login", actorr={"id": "u-1"})  # type: ignore[call-arg]


def test_empty_batch_is_rejected() -> None:
    with pytest.raises(ValidationError):
        IngestBatchIn(events=[])


# ---------------------------------------------------------------------------
# Document rendering
# ---------------------------------------------------------------------------
def test_document_is_ecs_shaped_and_sparse() -> None:
    """Empty containers are omitted: sparse docs compress better at scale."""
    event = AuditEvent(
        timestamp=datetime(2026, 8, 27, 10, 0, tzinfo=UTC),
        tenant_id="tenant-a",
        action="user.login",
        category=EventCategory.AUTHENTICATION,
        actor=Actor(id="u-42", type=ActorType.USER),
        source=Source(country_code="IN"),
    )
    document = event.to_document()

    assert document["@timestamp"] == "2026-08-27T10:00:00+00:00"
    assert document["event"]["action"] == "user.login"
    assert document["tenant"]["id"] == "tenant-a"
    assert document["actor"]["id"] == "u-42"
    # Unset objects are absent rather than present-but-empty.
    assert "change" not in document
    assert "http" not in document
    assert "labels" not in document


def test_writer_assigned_fields_are_absent_until_the_worker_sets_them() -> None:
    """An emitter cannot supply its own integrity block."""
    event = AuditEvent(
        timestamp=datetime(2026, 8, 27, 10, 0, tzinfo=UTC),
        tenant_id="tenant-a",
        action="user.login",
        category=EventCategory.AUTHENTICATION,
    )
    assert "integrity" not in event.to_document()


def test_bulk_target_ids_are_capped() -> None:
    """A genuinely larger batch should emit a summary plus per-item events."""
    with pytest.raises(ValidationError):
        AuditEventIn(
            action="credential.issue.bulk",
            target={"type": "credential", "ids": [f"vc-{i}" for i in range(1001)]},
        )


def test_event_id_can_be_supplied_for_idempotency() -> None:
    """A stable id makes an emitter retry safe: the ES write dedupes on it."""
    event = AuditEventIn(action="user.login", event_id="stable-key-1")
    assert event.to_domain(tenant_id="t").event_id == "stable-key-1"


def test_timestamp_defaults_to_now_when_omitted() -> None:
    before = datetime.now(UTC) - timedelta(seconds=1)
    domain = AuditEventIn(action="user.login").to_domain(tenant_id="t")
    assert domain.timestamp >= before
    assert domain.ingested_at is not None


class TestClockSkewDetection:
    """An emitter with a wrong clock corrupts the timeline silently.

    The record it produces is indistinguishable from a correct one, so nothing
    downstream can tell that an incident's chronology has been scrambled. These
    tests pin the two decisions that make the control useful: the event is
    *always* kept, and its timestamp is never rewritten - only annotated.
    """

    TENANT = "3d1f8c22-9b7e-4a51-8f6d-2e0b7c9a4d13"

    def _event(self, timestamp: datetime | None) -> AuditEventIn:
        return AuditEventIn(action=Action.USER_LOGIN.value, timestamp=timestamp)

    def test_timestamp_within_tolerance_is_not_flagged(self) -> None:
        recent = datetime.now(UTC) - timedelta(seconds=30)
        event = self._event(recent).to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=300)
        assert "clock_skew_suspect" not in event.labels

    def test_future_timestamp_beyond_tolerance_is_flagged(self) -> None:
        future = datetime.now(UTC) + timedelta(hours=2)
        event = self._event(future).to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=300)

        assert event.labels["clock_skew_suspect"] is True
        # Positive skew: the emitter claims the future.
        assert event.labels["clock_skew_seconds"] > 0

    def test_stale_timestamp_beyond_tolerance_is_flagged_with_negative_skew(self) -> None:
        stale = datetime.now(UTC) - timedelta(days=3)
        event = self._event(stale).to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=300)

        assert event.labels["clock_skew_suspect"] is True
        # The sign is what tells an operator "wrong clock" from "backfill".
        assert event.labels["clock_skew_seconds"] < 0

    def test_flagged_event_is_never_rejected_and_keeps_its_claimed_time(self) -> None:
        """Dropping evidence or silently correcting it are both worse than a flag."""
        future = datetime.now(UTC) + timedelta(days=365)
        event = self._event(future).to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=300)

        assert event.timestamp == future
        assert event.ingested_at < event.timestamp

    def test_absent_timestamp_is_never_flagged(self) -> None:
        """Defaulting to receipt time is not a skewed clock; it is no claim at all."""
        event = self._event(None).to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=300)
        assert "clock_skew_suspect" not in event.labels

    def test_check_is_disabled_when_no_tolerance_is_given(self) -> None:
        future = datetime.now(UTC) + timedelta(days=365)
        event = self._event(future).to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=None)
        assert "clock_skew_suspect" not in event.labels

    def test_emitter_labels_are_preserved_alongside_the_marker(self) -> None:
        future = datetime.now(UTC) + timedelta(hours=2)
        incoming = AuditEventIn(
            action=Action.USER_LOGIN.value, timestamp=future, labels={"batch_id": "b-1"}
        )
        event = incoming.to_domain(tenant_id=self.TENANT, max_clock_skew_seconds=300)

        assert event.labels["batch_id"] == "b-1"
        assert event.labels["clock_skew_suspect"] is True
