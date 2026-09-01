"""Authentication and authorisation.

Two kinds of caller
-------------------
**Service principal** (`x-api-key`). The main backend and its siblings. They have
already enforced RBAC on the user's behalf, so a service may write events and
read within a tenant it names explicitly. The key is compared in constant time
and matched against a list, so keys can be rotated with an overlap window.

**User principal** (`Authorization: Bearer <jwt>`). A platform access token,
validated with the same secret, issuer and audience the main backend uses, so no
separate login exists for this service.

Secure by default for user tokens
---------------------------------
An ordinary platform token carries no audit scopes, and this service has no
database access to resolve the platform's RBAC tables. Rather than guess, an
unscoped token is granted exactly one thing: read access to *its own* events,
with `actor_id` pinned so the filter cannot be widened. Broader access requires
either a token minted with explicit `audit_scopes`, or a service call from the
main backend which has already checked `require_permission`.

The failure mode of guessing here would be one user reading another's audit
trail, so the default is the narrowest useful grant rather than the most
convenient one.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass, field
from typing import Any, Final

import jwt
from jwt import (
    ExpiredSignatureError,
    InvalidAudienceError,
    InvalidIssuerError,
    InvalidTokenError,
)

from app.core.config import Settings
from app.core.logging import get_logger
from app.domain.enums import ActorType, Scope

logger = get_logger(__name__)

#: Claim carrying explicitly granted audit scopes, when the issuer sets one.
_SCOPES_CLAIM: Final[str] = "audit_scopes"

#: Header a service uses to name the tenant it is acting for.
TENANT_HEADER: Final[str] = "x-audit-tenant-id"
#: Header a service uses to record which human triggered the call. Recorded in
#: the audit-of-the-audit trail so a service-mediated read is still attributable.
ON_BEHALF_HEADER: Final[str] = "x-audit-on-behalf-of"
API_KEY_HEADER: Final[str] = "x-api-key"

#: Scopes a trusted internal service receives. Notably excludes ERASE and
#: CROSS_TENANT: destroying personal data and reading across tenants are
#: deliberate human decisions, not something a service key can do by itself.
_SERVICE_SCOPES: Final[frozenset[Scope]] = frozenset(
    {Scope.WRITE, Scope.READ, Scope.VERIFY, Scope.EXPORT}
)


class AuthenticationError(Exception):
    """No valid credential was presented."""


class AuthorizationError(Exception):
    """The caller is authenticated but lacks the required scope."""


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    subject: str
    """User UUID, or the service name for a service principal."""
    actor_type: ActorType
    tenant_id: str | None
    scopes: frozenset[Scope]
    email: str | None = None
    session_id: str | None = None
    on_behalf_of: str | None = None
    """The human a service call is acting for, when supplied."""
    restricted_to_self: bool = False
    """When true, reads are pinned to this principal's own events."""
    claims: dict[str, Any] = field(default_factory=dict, repr=False)
    """Raw token claims. Excluded from repr so they cannot leak into a log."""

    def require(self, *needed: Scope) -> None:
        """Assert the caller holds every required scope.

        Raises:
            AuthorizationError: any scope is missing.
        """
        missing = [scope for scope in needed if scope not in self.scopes]
        if missing:
            raise AuthorizationError(
                "missing required scope(s): " + ", ".join(sorted(s.value for s in missing))
            )

    def has(self, scope: Scope) -> bool:
        """Return True if the principal was granted ``scope``."""
        return scope in self.scopes

    @property
    def is_service(self) -> bool:
        """True for machine principals authenticated with ``x-api-key``."""
        return self.actor_type is ActorType.SERVICE

    @property
    def audit_identity(self) -> str:
        """How this principal is recorded in the audit-of-the-audit trail."""
        if self.on_behalf_of:
            return f"{self.subject} on behalf of {self.on_behalf_of}"
        return self.subject


class Authenticator:
    """Validates credentials and produces a `Principal`."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._api_keys = tuple(key.get_secret_value() for key in settings.SERVICE_API_KEYS)

    # --------------------------------------------------------------- api keys
    def verify_api_key(self, presented: str | None) -> bool:
        """Constant-time comparison against every configured key.

        `compare_digest` on each candidate, and the loop always runs to
        completion, so neither the value nor the position of a matching key can
        be recovered from response timing.
        """
        if not presented or not self._api_keys:
            return False
        matched = False
        for candidate in self._api_keys:
            if hmac.compare_digest(presented, candidate):
                matched = True
        return matched

    def service_principal(
        self,
        *,
        service_name: str,
        tenant_id: str | None,
        on_behalf_of: str | None,
    ) -> Principal:
        """Build the principal for an authenticated internal service."""
        return Principal(
            subject=service_name,
            actor_type=ActorType.SERVICE,
            tenant_id=tenant_id,
            scopes=_SERVICE_SCOPES,
            on_behalf_of=on_behalf_of,
        )

    # ------------------------------------------------------------------- JWT
    def verify_jwt(self, token: str) -> Principal:
        """Validate a platform access token and derive a principal.

        Signature, expiry, audience and issuer are all verified. `require`
        forces the claims to be present rather than merely consistent - a token
        without `exp` would otherwise validate forever.

        Raises:
            AuthenticationError: the token is missing, malformed, expired, or
                signed for a different audience or issuer.
        """
        try:
            claims = jwt.decode(
                token,
                self._settings.JWT_SECRET_KEY.get_secret_value(),
                algorithms=[self._settings.JWT_ALGORITHM],
                audience=self._settings.JWT_AUDIENCE,
                issuer=self._settings.JWT_ISSUER,
                leeway=self._settings.JWT_LEEWAY_SECONDS,
                options={
                    "require": ["exp", "iat", "sub"],
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_signature": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise AuthenticationError("token has expired") from exc
        except InvalidAudienceError as exc:
            raise AuthenticationError("token audience does not match this service") from exc
        except InvalidIssuerError as exc:
            raise AuthenticationError("token issuer is not recognised") from exc
        except InvalidTokenError as exc:
            # Deliberately generic: echoing the library's reason back to the
            # caller helps an attacker tune a forgery attempt.
            logger.warning("jwt_rejected", reason=str(exc))
            raise AuthenticationError("token is invalid") from exc

        identity = _parse_identity(claims.get("sub"))
        subject = identity.get("uuid") or identity.get("id")
        if not subject:
            raise AuthenticationError("token subject carries no user identifier")

        granted = _parse_scopes(claims.get(_SCOPES_CLAIM))
        restricted = not granted
        if restricted:
            # No explicit grant: self-service history only.
            granted = frozenset({Scope.READ})

        return Principal(
            subject=str(subject),
            actor_type=(ActorType.ADMIN if Scope.ADMIN in granted else ActorType.USER),
            tenant_id=_claim_str(claims.get("tenant_id")),
            scopes=granted,
            email=identity.get("email"),
            session_id=_claim_str(claims.get("sid")),
            restricted_to_self=restricted,
            claims=claims,
        )


def _parse_identity(subject: Any) -> dict[str, Any]:
    """Decode the platform's `sub` claim.

    The main backend stores `json.dumps({"email": ..., "uuid": ...})` in `sub`,
    but older tokens carry a bare string. Both are accepted so this service does
    not force a fleet-wide re-login to deploy.
    """
    if isinstance(subject, dict):
        return subject
    if isinstance(subject, str):
        text = subject.strip()
        if text.startswith("{"):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        return {"uuid": text}
    return {}


def _parse_scopes(raw: Any) -> frozenset[Scope]:
    """Parse the scopes claim, ignoring anything unrecognised.

    Unknown scope strings are dropped rather than rejected: a newer issuer may
    mint a scope this build predates, and failing the whole token would take the
    service down during a rollout. Dropping is safe because an unknown scope
    grants nothing.
    """
    if raw is None:
        return frozenset()
    if isinstance(raw, str):
        candidates = raw.replace(",", " ").split()
    elif isinstance(raw, (list, tuple)):
        candidates = [str(item) for item in raw]
    else:
        return frozenset()

    resolved: set[Scope] = set()
    for candidate in candidates:
        try:
            resolved.add(Scope(candidate.strip()))
        except ValueError:
            logger.debug("unknown_scope_ignored", scope=candidate)
    # ADMIN implies the ordinary read/verify/export grants, so an admin token
    # does not have to enumerate them.
    if Scope.ADMIN in resolved:
        resolved |= {Scope.READ, Scope.VERIFY, Scope.EXPORT}
    return frozenset(resolved)


def _claim_str(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None
