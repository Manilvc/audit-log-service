"""Authentication and authorisation.

One kind of caller
------------------
**Service principal** (`x-api-key`). The main backend and its siblings. They
have already enforced RBAC on the end user's behalf, so a service may write
events and read within the user trail it names explicitly via the
`x-audit-user-uuid` header. The key is compared in constant time and matched
against a list, so keys can be rotated with an overlap window.

There is no end-user credential. This service does not validate platform JWTs
and has no login of its own: it is reachable only by callers holding a service
key, and the isolation boundary for every call comes from the user-uuid header
rather than from a token claim.

User scoping
------------
A service key is not bound to a user, so `x-audit-user-uuid` is what decides
whose records a call may touch. Whoever holds a key can therefore name any
user - the key is the trust boundary, and the caller in front of it (the main
backend) is responsible for having checked `require_permission` first.

The header is validated for *shape* only (`UserRouter.validate_user_uuid`),
and it is required on every route that touches one user's records. Existence
is not checked, by design: the main backend resolves the subject user from its
own request context and authorises the caller against it before calling, so a
lookup here would re-answer a question that has already been answered - and
would put a network call to the caller in front of an audit write. The cost of
that choice is that a wrong-but-well-formed user uuid is accepted and its
events become unreachable by whoever should own them, which is a caller bug
rather than a leak: a read for user A can still only ever return user A's
events.

Scope grant
-----------
A valid key receives every scope, including ERASE, ADMIN and CROSS_USER. That
is a deliberate choice made when the end-user credential was removed: those
operations - crypto-shredding personal data, provisioning streams, reading
across user boundaries - would otherwise be unreachable, because nothing else
can mint a scoped principal. The consequence is that a leaked key is enough to
erase a data subject's personal data or read every user's trail, so the key
must be treated as a high-value secret: distinct per environment, rotated on a
schedule, and never shared with a component that only needs to write events.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Final

from app.core.config import Settings
from app.core.logging import get_logger
from app.domain.enums import ActorType, Scope

logger = get_logger(__name__)

#: Scopes a trusted internal service receives. Every scope this service defines:
#: see the module docstring for why ERASE, ADMIN and CROSS_USER are included
#: and what that means for how the key must be handled.
_SERVICE_SCOPES: Final[frozenset[Scope]] = frozenset(Scope)


class AuthenticationError(Exception):
    """No valid credential was presented."""


class AuthorizationError(Exception):
    """The caller is authenticated but lacks the required scope."""


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    subject: str
    """The service name, as the caller declared it for attribution."""
    actor_type: ActorType
    user_uuid: str | None
    """User named in the `x-audit-user-uuid` header, when one was sent.

    Validated for shape, never for existence. `None` only on the routes that
    need no user: the health probes, and a cross-user read.
    """
    scopes: frozenset[Scope]
    on_behalf_of: str | None = None
    """The human a service call is acting for, when supplied."""
    api_key_id: str | None = None
    """Which issued key authenticated this call, when one did.

    None for the env-configured service keys, which have no record to point at.
    Recorded so a compromised key's activity can be read straight off the trail.
    """

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
        """True for machine principals authenticated with ``x-api-key``.

        Always true today - the service key is the only credential - but the
        call sites that branch on it read more clearly than a bare `True`, and
        it stays correct if a second principal kind is ever reintroduced.
        """
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
        user_uuid: str | None,
        on_behalf_of: str | None,
    ) -> Principal:
        """Build the principal for a caller holding an env-configured key.

        The admin plane: every scope, and the user comes from the header
        because the credential is not bound to one.
        """
        return Principal(
            subject=service_name,
            actor_type=ActorType.SERVICE,
            user_uuid=user_uuid,
            scopes=_SERVICE_SCOPES,
            on_behalf_of=on_behalf_of,
        )

    def issued_key_principal(
        self,
        *,
        key_id: str,
        domain: str,
        user_uuid: str,
        scopes: frozenset[Scope],
        on_behalf_of: str | None,
    ) -> Principal:
        """Build the principal for a caller holding an issued key.

        Three differences from the admin plane, and each one is the point of
        issuing keys at all:

        * the user comes from the **key**, not from a header, so the caller
          cannot name someone else's;
        * the scopes are whatever that key was granted, normally write only;
        * `subject` is the domain the key was issued to - a verified identity,
          unlike the `x-service-name` header, which is an unchecked claim.

        Takes primitives rather than the stored record, so this module stays
        free of any dependency on how keys are persisted.
        """
        return Principal(
            subject=domain,
            actor_type=ActorType.SERVICE,
            user_uuid=user_uuid,
            scopes=scopes,
            on_behalf_of=on_behalf_of,
            api_key_id=key_id,
        )
