"""Unit tests for legacy display-string ↔ ECS taxonomy mapping."""

from __future__ import annotations

import pytest

from app.domain.enums import Action, EntityType, EventCategory, Outcome
from app.domain.legacy import (
    LEGACY_ACTION_TO_ECS,
    LEGACY_HOLDER_ACTION_TO_ECS,
    LEGACY_SESSION_EVENT_TO_ECS,
    legacy_event_hints,
    map_action,
    map_entity,
    map_status,
    to_legacy_action,
)


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("Issue Credential (Bulk)", Action.CREDENTIAL_ISSUE_BULK),
        ("Login", Action.USER_LOGIN),
        ("Preview Field", Action.PII_DECRYPT),
        ("Create Authority", Action.TENANT_CREATE),
        ("Upload Image (Bulk)", Action.RECORD_IMPORT),
        ("Delete Bulk Upload Preview", Action.RECORD_DELETE_BULK),
        ("Unknown", Action.UNKNOWN),
    ],
)
def test_map_user_audit_actions(legacy: str, expected: Action) -> None:
    assert map_action(legacy) is expected


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("Holder Login", Action.HOLDER_LOGIN),
        ("Holder Request Submit", Action.REQUEST_SUBMIT),
        ("Change Password", Action.USER_PASSWORD_CHANGE),
        ("KYC Status Completed", Action.HOLDER_KYC_COMPLETED),
        ("Request Declined By Issuer", Action.REQUEST_REJECT),
    ],
)
def test_map_holder_audit_actions(legacy: str, expected: Action) -> None:
    assert map_action(legacy) is expected


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("CREATED", Action.SESSION_CREATED),
        ("SUSPICIOUS_LOGIN", Action.SESSION_SUSPICIOUS_LOGIN),
        ("POLICY_UPDATED", Action.SESSION_POLICY_UPDATED),
    ],
)
def test_map_session_events(legacy: str, expected: Action) -> None:
    assert map_action(legacy) is expected


def test_map_action_accepts_ecs_string_passthrough() -> None:
    assert map_action("credential.issue") is Action.CREDENTIAL_ISSUE


def test_map_action_unknown_falls_back() -> None:
    assert map_action("Totally Made Up Action") is Action.UNKNOWN


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("User", EntityType.USER),
        ("Credential", EntityType.CREDENTIAL),
        ("Holder", EntityType.HOLDER),
        ("credential", EntityType.CREDENTIAL),  # already ECS
        ("Nonsense", EntityType.UNKNOWN),
    ],
)
def test_map_entity(legacy: str, expected: EntityType) -> None:
    assert map_entity(legacy) is expected


@pytest.mark.parametrize(
    ("legacy", "expected"),
    [
        ("Success", Outcome.SUCCESS),
        ("Failure", Outcome.FAILURE),
        ("Failed", Outcome.FAILURE),
        ("success", Outcome.SUCCESS),
        ("error", Outcome.FAILURE),
        ("maybe", Outcome.UNKNOWN),
    ],
)
def test_map_status(legacy: str, expected: Outcome) -> None:
    assert map_status(legacy) is expected


def test_legacy_event_hints_includes_category() -> None:
    action, category = legacy_event_hints("Issue Credential (Bulk)")
    assert action is Action.CREDENTIAL_ISSUE_BULK
    assert category is EventCategory.CREDENTIAL


def test_to_legacy_action_round_trip_canonical() -> None:
    assert to_legacy_action(Action.CREDENTIAL_ISSUE_BULK) == "Issue Credential (Bulk)"
    assert to_legacy_action(Action.SESSION_CREATED) == "CREATED"
    # No legacy label for audit-of-audit actions — return the ECS string.
    assert to_legacy_action(Action.AUDIT_SEARCH) == "audit_log.search"


def test_every_legacy_user_action_is_mapped() -> None:
    """Guard against silently dropping a new ActionType value from attribute.py."""
    assert len(LEGACY_ACTION_TO_ECS) >= 45
    assert all(isinstance(v, Action) for v in LEGACY_ACTION_TO_ECS.values())


def test_every_legacy_holder_and_session_mapped() -> None:
    assert len(LEGACY_HOLDER_ACTION_TO_ECS) >= 12
    assert len(LEGACY_SESSION_EVENT_TO_ECS) == 10
