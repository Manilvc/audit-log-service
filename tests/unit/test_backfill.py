"""Unit tests for legacy NDJSON → ingest payload mapping (historical backfill)."""

from __future__ import annotations

from app.domain.enums import Action, EntityType, Outcome
from app.domain.legacy import map_action, map_entity, map_status
from app.tools.backfill import map_legacy_row


def test_map_user_audit_row() -> None:
    event = map_legacy_row(
        {
            "source": "user_audit_log",
            "tenant_id": "t-1",
            "uuid": "evt-1",
            "user_id": 9,
            "user_uuid": "u-9",
            "entity": "Credential",
            "action": "Issue Credential (Bulk)",
            "status": "Success",
            "details": "issued 3",
            "ip_address": "203.0.113.9",
            "location_country": "IN",
            "created_at": "2026-01-15T10:00:00",
        }
    )
    assert event["event_id"] == "evt-1"
    assert event["action"] == Action.CREDENTIAL_ISSUE_BULK
    assert event["outcome"] == Outcome.SUCCESS
    assert event["actor"]["id"] == "u-9"
    assert event["target"]["type"] == EntityType.CREDENTIAL
    assert event["timestamp"].endswith("+00:00")
    assert event["labels"]["backfill"] is True


def test_map_session_row() -> None:
    event = map_legacy_row(
        {
            "source": "session_audit_log",
            "tenant_id": "t-1",
            "id": 42,
            "session_uuid": "s-1",
            "user_id": 7,
            "event_type": "CREATED",
            "ip_address": "198.51.100.1",
            "location_country_code": "US",
        }
    )
    assert event["event_id"] == "session-s-1-CREATED-42"
    assert event["action"] == Action.SESSION_CREATED
    assert event["target"]["id"] == "s-1"


def test_map_holder_row() -> None:
    event = map_legacy_row(
        {
            "source": "holder_audit_log",
            "tenant_id": "t-1",
            "uuid": "h-evt-1",
            "holder_id": 3,
            "holder_uuid": "holder-3",
            "entity": "Holder",
            "action": "Holder Login",
            "status": "Failed",
        }
    )
    assert event["action"] == Action.HOLDER_LOGIN
    assert event["outcome"] == Outcome.FAILURE
    assert event["actor"]["type"] == "holder"


def test_legacy_helpers_used() -> None:
    assert map_action("Login") is Action.USER_LOGIN
    assert map_entity("User") is EntityType.USER
    assert map_status("Failed") is Outcome.FAILURE
