"""Authentication and authorisation.

The default granted to an unscoped platform token is the security decision worth
testing hardest: if it were wrong, any logged-in user could read their whole
tenant's audit trail.
"""

from __future__ import annotations

import datetime as dt
import json

import jwt
import pytest

from app.core.config import Settings
from app.core.security.auth import (
    AuthenticationError,
    Authenticator,
    AuthorizationError,
    Principal,
)
from app.domain.enums import ActorType, Scope

SECRET = "unit-test-signing-secret-0123456789abcdef"
AUDIENCE = "everycred-api"
ISSUER = "Your-Issuer"


def _token(
    *,
    secret: str = SECRET,
    audience: str = AUDIENCE,
    issuer: str = ISSUER,
    tenant_id: str | None = "tenant-a",
    scopes: object = None,
    expires_in: int = 900,
    algorithm: str = "HS256",
    subject: object = None,
) -> str:
    now = dt.datetime.now(dt.UTC)
    identity = (
        subject
        if subject is not None
        else json.dumps({"email": "alice@example.com", "uuid": "u-42"})
    )
    claims: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "iat": now.timestamp(),
        "exp": (now + dt.timedelta(seconds=expires_in)).timestamp(),
        "sub": identity,
        "sid": "sess-1",
    }
    if tenant_id:
        claims["tenant_id"] = tenant_id
    if scopes is not None:
        claims["audit_scopes"] = scopes
    return jwt.encode(claims, secret, algorithm=algorithm)


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


def test_service_principal_has_write_but_not_erase_or_cross_tenant(
    authenticator: Authenticator,
) -> None:
    """A service key must not be able to destroy data or cross tenants.

    Those are deliberate human decisions. A leaked service key should not be
    able to erase a data subject's history or read another tenant's trail.
    """
    principal = authenticator.service_principal(
        service_name="everycred-backend", tenant_id="tenant-a", on_behalf_of="u-42"
    )
    assert principal.has(Scope.WRITE)
    assert principal.has(Scope.READ)
    assert not principal.has(Scope.ERASE)
    assert not principal.has(Scope.CROSS_TENANT)
    assert not principal.has(Scope.ADMIN)
    assert principal.actor_type is ActorType.SERVICE


def test_service_principal_records_the_human_it_acts_for(
    authenticator: Authenticator,
) -> None:
    """Attribution must survive a service-mediated call."""
    principal = authenticator.service_principal(
        service_name="everycred-backend", tenant_id="tenant-a", on_behalf_of="u-42"
    )
    assert principal.audit_identity == "everycred-backend on behalf of u-42"


# ---------------------------------------------------------------------------
# JWT validation
# ---------------------------------------------------------------------------
def test_valid_token_produces_a_principal(authenticator: Authenticator) -> None:
    principal = authenticator.verify_jwt(_token())
    assert principal.subject == "u-42"
    assert principal.email == "alice@example.com"
    assert principal.tenant_id == "tenant-a"
    assert principal.session_id == "sess-1"


def test_legacy_bare_string_subject_is_accepted(
    authenticator: Authenticator,
) -> None:
    """Older platform tokens put a bare uuid in `sub`.

    Rejecting them would force a fleet-wide re-login just to deploy this service.
    """
    principal = authenticator.verify_jwt(_token(subject="u-legacy"))
    assert principal.subject == "u-legacy"


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"secret": "attacker-secret-0123456789abcdefghijklmn"}, "forged signature"),
        ({"audience": "some-other-api"}, "token minted for a different service"),
        ({"issuer": "evil-issuer"}, "untrusted issuer"),
        ({"expires_in": -3600}, "expired token"),
    ],
)
def test_invalid_tokens_are_rejected(
    authenticator: Authenticator, kwargs: dict, reason: str
) -> None:
    with pytest.raises(AuthenticationError):
        authenticator.verify_jwt(_token(**kwargs))


def test_unsigned_token_is_rejected(authenticator: Authenticator) -> None:
    """The `alg: none` attack.

    Algorithms are pinned in `jwt.decode`, so an unsigned token cannot pass.
    """
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u-42", "exp": 9999999999, "iat": 0},
        key="",
        algorithm="none",
    )
    with pytest.raises(AuthenticationError):
        authenticator.verify_jwt(forged)


def test_token_without_expiry_is_rejected(authenticator: Authenticator) -> None:
    """A token with no `exp` would be valid forever."""
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "u-42", "iat": 0}, SECRET, algorithm="HS256"
    )
    with pytest.raises(AuthenticationError):
        authenticator.verify_jwt(forged)


def test_token_without_a_user_identifier_is_rejected(
    authenticator: Authenticator,
) -> None:
    """An unattributable principal cannot be recorded in an audit trail."""
    with pytest.raises(AuthenticationError, match="no user identifier"):
        authenticator.verify_jwt(_token(subject=json.dumps({"email": "a@b.c"})))


def test_garbage_is_rejected(authenticator: Authenticator) -> None:
    with pytest.raises(AuthenticationError):
        authenticator.verify_jwt("not-a-token")


def test_rejection_message_does_not_leak_the_library_reason(
    authenticator: Authenticator,
) -> None:
    """A precise reason helps an attacker tune a forgery attempt."""
    with pytest.raises(AuthenticationError) as caught:
        authenticator.verify_jwt("a.b.c")
    assert str(caught.value) == "token is invalid"


# ---------------------------------------------------------------------------
# Scope derivation - the secure default
# ---------------------------------------------------------------------------
def test_unscoped_token_gets_self_service_read_only(
    authenticator: Authenticator,
) -> None:
    """The central authorisation decision.

    A plain platform token carries no audit scopes, and this service cannot read
    the platform's RBAC tables. Rather than guess, it grants read access pinned
    to the caller's own events.
    """
    principal = authenticator.verify_jwt(_token())
    assert principal.scopes == frozenset({Scope.READ})
    assert principal.restricted_to_self is True
    assert not principal.has(Scope.EXPORT)
    assert not principal.has(Scope.ERASE)
    assert not principal.has(Scope.ADMIN)


def test_explicitly_scoped_token_is_not_self_restricted(
    authenticator: Authenticator,
) -> None:
    principal = authenticator.verify_jwt(_token(scopes=["audit:read", "audit:export"]))
    assert principal.restricted_to_self is False
    assert principal.has(Scope.EXPORT)


def test_admin_scope_implies_the_ordinary_grants(
    authenticator: Authenticator,
) -> None:
    """An admin token need not enumerate read/verify/export."""
    principal = authenticator.verify_jwt(_token(scopes=["audit:admin"]))
    assert principal.has(Scope.READ)
    assert principal.has(Scope.VERIFY)
    assert principal.has(Scope.EXPORT)
    assert principal.actor_type is ActorType.ADMIN
    # Admin does NOT imply erase or cross-tenant: both stay explicit.
    assert not principal.has(Scope.ERASE)
    assert not principal.has(Scope.CROSS_TENANT)


def test_unknown_scopes_are_ignored_not_fatal(
    authenticator: Authenticator,
) -> None:
    """A newer issuer may mint a scope this build predates.

    Failing the whole token would take the service down mid-rollout; an unknown
    scope grants nothing, so dropping it is safe.
    """
    principal = authenticator.verify_jwt(_token(scopes=["audit:read", "audit:from-the-future"]))
    assert principal.scopes == frozenset({Scope.READ})
    assert principal.restricted_to_self is False


@pytest.mark.parametrize(
    "raw", ["audit:read audit:export", "audit:read,audit:export", ["audit:read"]]
)
def test_scope_claim_accepts_common_encodings(authenticator: Authenticator, raw: object) -> None:
    principal = authenticator.verify_jwt(_token(scopes=raw))
    assert Scope.READ in principal.scopes


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------
def test_require_lists_every_missing_scope() -> None:
    principal = Principal(
        subject="u-1",
        actor_type=ActorType.USER,
        tenant_id="tenant-a",
        scopes=frozenset({Scope.READ}),
    )
    principal.require(Scope.READ)  # no raise

    with pytest.raises(AuthorizationError) as caught:
        principal.require(Scope.READ, Scope.ERASE, Scope.ADMIN)
    message = str(caught.value)
    assert "audit:erase" in message
    assert "audit:admin" in message
    assert "audit:read" not in message


def test_principal_repr_does_not_expose_token_claims() -> None:
    """Claims must not reach a log line through an accidental repr."""
    principal = Principal(
        subject="u-1",
        actor_type=ActorType.USER,
        tenant_id="tenant-a",
        scopes=frozenset({Scope.READ}),
        claims={"secret_thing": "must-not-appear"},
    )
    assert "must-not-appear" not in repr(principal)
