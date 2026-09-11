"""Authentication and authorisation.

The service API key is the only credential, so key comparison is the security
decision worth testing hardest: a near-miss that matched, or a timing-observable
compare, would hand over every user's audit trail.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.security.auth import (
    Authenticator,
    AuthorizationError,
    Principal,
)
from app.domain.enums import ActorType, Scope


@pytest.fixture
def authenticator(settings: Settings) -> Authenticator:
    return Authenticator(settings)


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
def test_valid_api_key_is_accepted(authenticator: Authenticator) -> None:
    assert authenticator.verify_api_key("test-key-one")
    # Rotation overlap: the outgoing key stays valid alongside the new one.
    assert authenticator.verify_api_key("test-key-two")


@pytest.mark.parametrize(
    "presented",
    [None, "", "wrong", "test-key-on", "test-key-onex", "TEST-KEY-ONE"],
)
def test_invalid_api_key_is_rejected(authenticator: Authenticator, presented: str | None) -> None:
    """Including near-misses: no prefix matching, no case folding."""
    assert not authenticator.verify_api_key(presented)


def test_no_key_is_accepted_when_none_are_configured() -> None:
    """An empty allow-list must deny, never allow-all.

    A misconfigured deployment that dropped SERVICE_API_KEYS would otherwise
    turn the whole audit trail into an open endpoint.
    """
    settings = Settings(SERVICE_API_KEYS=[])
    authenticator = Authenticator(settings)
    assert not authenticator.verify_api_key("anything")
    assert not authenticator.verify_api_key("")


def test_service_principal_carries_every_scope(authenticator: Authenticator) -> None:
    """The key is the only credential, so it must grant every operation.

    Erase, admin and cross-user were previously reachable only through a
    scoped user token. With that path gone, withholding them here would leave
    erasure, user dedication and cross-user search permanently 403.
    """
    principal = authenticator.service_principal(
        service_name="everycred-backend", user_uuid="user-a", on_behalf_of="u-42"
    )
    assert principal.scopes == frozenset(Scope)
    assert principal.actor_type is ActorType.SERVICE
    assert principal.is_service


def test_service_principal_takes_its_user_from_the_header(
    authenticator: Authenticator,
) -> None:
    """The user is per-request, not bound to the key."""
    principal = authenticator.service_principal(
        service_name="everycred-backend", user_uuid="user-a", on_behalf_of=None
    )
    assert principal.user_uuid == "user-a"

    unscoped = authenticator.service_principal(
        service_name="everycred-backend", user_uuid=None, on_behalf_of=None
    )
    assert unscoped.user_uuid is None


def test_service_principal_records_the_human_it_acts_for(
    authenticator: Authenticator,
) -> None:
    """Attribution must survive a service-mediated call."""
    principal = authenticator.service_principal(
        service_name="everycred-backend", user_uuid="user-a", on_behalf_of="u-42"
    )
    assert principal.audit_identity == "everycred-backend on behalf of u-42"


def test_audit_identity_falls_back_to_the_service_name(
    authenticator: Authenticator,
) -> None:
    principal = authenticator.service_principal(
        service_name="everycred-backend", user_uuid="user-a", on_behalf_of=None
    )
    assert principal.audit_identity == "everycred-backend"


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------
def test_require_lists_every_missing_scope() -> None:
    principal = Principal(
        subject="svc-1",
        actor_type=ActorType.SERVICE,
        user_uuid="user-a",
        scopes=frozenset({Scope.READ}),
    )
    principal.require(Scope.READ)  # no raise

    with pytest.raises(AuthorizationError) as caught:
        principal.require(Scope.READ, Scope.ERASE, Scope.ADMIN)
    message = str(caught.value)
    assert "audit:erase" in message
    assert "audit:admin" in message
    assert "audit:read" not in message
