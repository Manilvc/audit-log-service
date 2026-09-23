"""Presentation rules for the audit console listing.

The stored event is ECS-shaped and machine-first: `event.action` is
`credential.issue`, `event.category` is `credential`, `event.severity` is one of
five levels. A console table is human-first: it shows "Credential issued" under
a *Verification* / *Issuance* / *Revocation* heading with an Info / Warn /
Critical badge. Something has to translate, and this module is it.

Why the translation lives here rather than in the frontend
----------------------------------------------------------
The console's filter chips and its Category column have to agree: clicking
"Issuance" must return exactly the rows the table labels *Issuance*. That
agreement is a property of one mapping, so the mapping is defined once, server
side, and both the filter and the label are derived from it
(`FilterPreset.actions` reads the same table `display_category` does). Splitting
it across two codebases is how a chip ends up hiding rows it should show.

Everything here is a pure function over an already-stored document. Nothing is
persisted in these terms: the ECS values stay canonical, so re-labelling a
category later is a deploy of this module and not a six-year reindex.

The three vocabularies
----------------------
* `DisplayCategory` - what the Category column shows. A grouping *by activity*
  (issuance, revocation, verification), which is the question an auditor asks,
  whereas ECS `event.category` groups by subsystem.
* `SeverityTier` - the three badges the UI draws, collapsed from the five
  stored levels.
* `FilterPreset` - the chips above the table.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final

from app.core.constants import FILTER_PRESET_ALL, MAX_ROW_TITLE_LENGTH
from app.domain.enums import Action, ActorType, Severity
from app.domain.events import PROTECTED_PLACEHOLDER


class DisplayCategory(StrEnum):
    """The Category column: what kind of activity this event was.

    Values are lowercase codes, stable like every other enum in the domain.
    The console title-cases them for display; sending "Issuance" over the wire
    would make the label the contract, and a wording change would then break
    every client filtering on it.
    """

    ISSUANCE = "issuance"
    """Minting a credential and the cryptographic steps that finish it."""
    REVOCATION = "revocation"
    VERIFICATION = "verification"
    APPROVAL = "approval"
    """A request moving through review - submitted, approved, rejected."""
    ACCESS = "access"
    """Someone read, shared or exported data, or a permission changed."""
    LIFECYCLE = "lifecycle"
    """A credential or record changing state without being created or revoked:
    reissued, renewed, suspended, expired."""
    AUTHENTICATION = "authentication"
    ADMINISTRATION = "administration"
    """Configuration, roles, keys, issuers, tenants - who runs the platform."""
    INTEGRATION = "integration"
    AUDIT = "audit"
    """Reads of this service's own trail (HIPAA 164.312(b))."""
    OTHER = "other"


class SeverityTier(StrEnum):
    """The badge drawn next to a row.

    Three, not five. The stored scale distinguishes LOW from INFO and MEDIUM
    from HIGH because alerting rules need that resolution; a reviewer scanning
    a table needs "routine / look at this / stop what you are doing". Collapsing
    happens on read so the stored severity keeps its full precision.
    """

    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


class FilterPreset(StrEnum):
    """A filter chip above the table."""

    ALL = FILTER_PRESET_ALL
    CRITICAL = "critical"
    REVOCATION = "revocation"
    APPROVAL = "approval"
    ISSUANCE = "issuance"
    VERIFICATION = "verification"

    @property
    def actions(self) -> tuple[str, ...]:
        """Actions this chip selects, or empty when it does not filter by action.

        Derived from the same table that labels the Category column, so a chip
        can never disagree with the rows it returns.

        A closed list rather than a prefix query: `terms` on a keyword is the
        cheapest filter Lucene has, and it keeps an emitter's unrecognised
        action out of a chip it was never classified into. Such an action is
        still *labelled* by prefix (see `display_category`), so it appears in
        the table under All with a sensible category - it just will not be
        pulled in by a chip that does not know about it.
        """
        category = _PRESET_CATEGORY.get(self)
        if category is None:
            return ()
        return _CATEGORY_ACTIONS[category]

    @property
    def severities(self) -> tuple[Severity, ...]:
        """Severities this chip selects, or empty when it does not filter by one.

        Only `CRITICAL` does, and it selects exactly `Severity.CRITICAL` so the
        chip matches the badge: a row that does not draw a red Critical badge
        must not appear under the Critical chip.
        """
        return (Severity.CRITICAL,) if self is FilterPreset.CRITICAL else ()


# ---------------------------------------------------------------------------
# Action -> display category
# ---------------------------------------------------------------------------
# Exact actions first. Everything in `app.domain.enums.Action` is classified
# here; a new action added there without a line here falls through to the
# prefix table below, which degrades to a reasonable label rather than to
# "other".
_ACTION_CATEGORY: Final[dict[str, DisplayCategory]] = {
    # -------------------------------------------------------------- issuance
    Action.CREDENTIAL_ISSUE: DisplayCategory.ISSUANCE,
    Action.CREDENTIAL_ISSUE_BULK: DisplayCategory.ISSUANCE,
    # Signing and anchoring are the steps that *complete* an issuance, so they
    # belong with it: a reviewer asking "how was this credential issued" wants
    # all three, and splitting them off would hide the cryptographic evidence
    # behind a different chip.
    Action.CREDENTIAL_SIGN: DisplayCategory.ISSUANCE,
    Action.CREDENTIAL_ANCHOR: DisplayCategory.ISSUANCE,
    # ------------------------------------------------------------ revocation
    Action.CREDENTIAL_REVOKE: DisplayCategory.REVOCATION,
    Action.CREDENTIAL_REVOKE_BULK: DisplayCategory.REVOCATION,
    # ---------------------------------------------------------- verification
    Action.CREDENTIAL_VERIFY: DisplayCategory.VERIFICATION,
    Action.HOLDER_KYC_VALIDATE: DisplayCategory.VERIFICATION,
    Action.HOLDER_KYC_COMPLETED: DisplayCategory.VERIFICATION,
    Action.SUREPASS_VERIFY: DisplayCategory.VERIFICATION,
    # -------------------------------------------------------------- approval
    Action.REQUEST_SUBMIT: DisplayCategory.APPROVAL,
    Action.REQUEST_APPROVE: DisplayCategory.APPROVAL,
    Action.REQUEST_REJECT: DisplayCategory.APPROVAL,
    Action.REQUEST_SEND: DisplayCategory.APPROVAL,
    Action.REQUEST_MOVE_TO_DRAFT: DisplayCategory.APPROVAL,
    # ---------------------------------------------------------------- access
    Action.CREDENTIAL_VIEW: DisplayCategory.ACCESS,
    Action.CREDENTIAL_SHARE: DisplayCategory.ACCESS,
    Action.CREDENTIAL_SHARE_BULK: DisplayCategory.ACCESS,
    Action.CREDENTIAL_DOWNLOAD: DisplayCategory.ACCESS,
    Action.RECORD_EXPORT: DisplayCategory.ACCESS,
    Action.DATA_EXPORT: DisplayCategory.ACCESS,
    Action.DATA_BULK_READ: DisplayCategory.ACCESS,
    Action.PII_DECRYPT: DisplayCategory.ACCESS,
    Action.PERMISSION_GRANT: DisplayCategory.ACCESS,
    Action.PERMISSION_REVOKE: DisplayCategory.ACCESS,
    Action.PERMISSION_DENIED: DisplayCategory.ACCESS,
    Action.CONSENT_GRANT: DisplayCategory.ACCESS,
    Action.CONSENT_WITHDRAW: DisplayCategory.ACCESS,
    Action.CONSENT_UPDATE: DisplayCategory.ACCESS,
    Action.CONSENT_NOTICE_VIEW: DisplayCategory.ACCESS,
    # ------------------------------------------------------------- lifecycle
    Action.CREDENTIAL_REISSUE: DisplayCategory.LIFECYCLE,
    Action.CREDENTIAL_RENEW: DisplayCategory.LIFECYCLE,
    Action.CREDENTIAL_SUSPEND: DisplayCategory.LIFECYCLE,
    Action.CREDENTIAL_UNSUSPEND: DisplayCategory.LIFECYCLE,
    Action.CREDENTIAL_EXPIRE: DisplayCategory.LIFECYCLE,
    Action.RECORD_CREATE: DisplayCategory.LIFECYCLE,
    Action.RECORD_CREATE_BULK: DisplayCategory.LIFECYCLE,
    Action.RECORD_UPDATE: DisplayCategory.LIFECYCLE,
    Action.RECORD_DELETE: DisplayCategory.LIFECYCLE,
    Action.RECORD_DELETE_BULK: DisplayCategory.LIFECYCLE,
    Action.RECORD_IMPORT: DisplayCategory.LIFECYCLE,
    Action.RECORD_VALIDATE_BULK: DisplayCategory.LIFECYCLE,
    Action.SUBJECT_CREATE: DisplayCategory.LIFECYCLE,
    Action.SUBJECT_UPDATE: DisplayCategory.LIFECYCLE,
    Action.SUBJECT_DELETE: DisplayCategory.LIFECYCLE,
    Action.SUBJECT_FIELD_UPDATE: DisplayCategory.LIFECYCLE,
    Action.REQUEST_CREATE: DisplayCategory.LIFECYCLE,
    Action.REQUEST_UPDATE: DisplayCategory.LIFECYCLE,
    Action.REQUEST_DELETE: DisplayCategory.LIFECYCLE,
    Action.REQUEST_DELETE_BULK: DisplayCategory.LIFECYCLE,
    # -------------------------------------------------------- authentication
    Action.USER_LOGIN: DisplayCategory.AUTHENTICATION,
    Action.USER_LOGIN_FAILED: DisplayCategory.AUTHENTICATION,
    Action.USER_LOGOUT: DisplayCategory.AUTHENTICATION,
    Action.USER_REGISTER: DisplayCategory.AUTHENTICATION,
    Action.USER_PASSWORD_FORGOT: DisplayCategory.AUTHENTICATION,
    Action.USER_PASSWORD_RESET: DisplayCategory.AUTHENTICATION,
    Action.USER_PASSWORD_CHANGE: DisplayCategory.AUTHENTICATION,
    Action.USER_MFA_ENROLL: DisplayCategory.AUTHENTICATION,
    Action.USER_MFA_VERIFY: DisplayCategory.AUTHENTICATION,
    Action.USER_OTP_SEND: DisplayCategory.AUTHENTICATION,
    Action.USER_OTP_VERIFY: DisplayCategory.AUTHENTICATION,
    Action.USER_ACCOUNT_LOCKED: DisplayCategory.AUTHENTICATION,
    Action.USER_ACCOUNT_UNLOCKED: DisplayCategory.AUTHENTICATION,
    Action.USER_MOBILE_REGISTER: DisplayCategory.AUTHENTICATION,
    Action.USER_MOBILE_UPDATE: DisplayCategory.AUTHENTICATION,
    Action.USER_IMPERSONATE: DisplayCategory.AUTHENTICATION,
    Action.HOLDER_LOGIN: DisplayCategory.AUTHENTICATION,
    Action.HOLDER_REGISTER: DisplayCategory.AUTHENTICATION,
    # -------------------------------------------------------- administration
    Action.USER_PROFILE_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.USER_DELETE: DisplayCategory.ADMINISTRATION,
    Action.HOLDER_PROFILE_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.HOLDER_DELETE: DisplayCategory.ADMINISTRATION,
    Action.ROLE_CREATE: DisplayCategory.ADMINISTRATION,
    Action.ROLE_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.ROLE_DELETE: DisplayCategory.ADMINISTRATION,
    Action.API_KEY_CREATE: DisplayCategory.ADMINISTRATION,
    Action.API_KEY_REVOKE: DisplayCategory.ADMINISTRATION,
    Action.API_KEY_USED: DisplayCategory.ADMINISTRATION,
    Action.GROUP_CREATE: DisplayCategory.ADMINISTRATION,
    Action.GROUP_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.GROUP_DELETE: DisplayCategory.ADMINISTRATION,
    Action.ISSUER_CREATE: DisplayCategory.ADMINISTRATION,
    Action.ISSUER_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.ISSUER_DELETE: DisplayCategory.ADMINISTRATION,
    Action.ISSUER_ACTIVATE: DisplayCategory.ADMINISTRATION,
    Action.ISSUER_DEACTIVATE: DisplayCategory.ADMINISTRATION,
    Action.CONFIG_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.TENANT_CREATE: DisplayCategory.ADMINISTRATION,
    Action.TENANT_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.TENANT_SUSPEND: DisplayCategory.ADMINISTRATION,
    Action.TEMPLATE_CREATE: DisplayCategory.ADMINISTRATION,
    Action.TEMPLATE_UPDATE: DisplayCategory.ADMINISTRATION,
    Action.TEMPLATE_DELETE: DisplayCategory.ADMINISTRATION,
    # ----------------------------------------------------------- integration
    Action.WEBHOOK_SEND: DisplayCategory.INTEGRATION,
    Action.WEBHOOK_RECEIVE: DisplayCategory.INTEGRATION,
    Action.EXTERNAL_API_CALL: DisplayCategory.INTEGRATION,
    Action.DIGILOCKER_PULL: DisplayCategory.INTEGRATION,
    # ----------------------------------------------------------------- audit
    Action.AUDIT_SEARCH: DisplayCategory.AUDIT,
    Action.AUDIT_EXPORT: DisplayCategory.AUDIT,
    Action.AUDIT_INTEGRITY_VERIFY: DisplayCategory.AUDIT,
    Action.AUDIT_ERASURE_REQUEST: DisplayCategory.AUDIT,
    Action.AUDIT_CROSS_USER_ACCESS: DisplayCategory.AUDIT,
    # ----------------------------------------------------------------- other
    Action.SESSION_CREATED: DisplayCategory.AUTHENTICATION,
    Action.SESSION_REFRESHED: DisplayCategory.AUTHENTICATION,
    Action.SESSION_IDLE_EXPIRED: DisplayCategory.AUTHENTICATION,
    Action.SESSION_ABSOLUTE_EXPIRED: DisplayCategory.AUTHENTICATION,
    Action.SESSION_FORCE_TERMINATED: DisplayCategory.AUTHENTICATION,
    Action.SESSION_SELF_LOGOUT: DisplayCategory.AUTHENTICATION,
    Action.SESSION_LOGOUT_ALL: DisplayCategory.AUTHENTICATION,
    Action.SESSION_SUSPICIOUS_LOGIN: DisplayCategory.AUTHENTICATION,
    Action.SESSION_LIMIT_EVICTED: DisplayCategory.AUTHENTICATION,
    Action.SESSION_POLICY_UPDATED: DisplayCategory.ADMINISTRATION,
}

# Fallback for an action this build has never seen - an emitter may ship a new
# verb ahead of the enum. Ordered: longest/most specific prefix first, exactly
# like `enums._ACTION_PREFIX_CATEGORY`.
_PREFIX_CATEGORY: Final[tuple[tuple[str, DisplayCategory], ...]] = (
    ("credential.issue", DisplayCategory.ISSUANCE),
    ("credential.revoke", DisplayCategory.REVOCATION),
    ("credential.verify", DisplayCategory.VERIFICATION),
    ("credential.", DisplayCategory.LIFECYCLE),
    ("request.", DisplayCategory.APPROVAL),
    ("record.", DisplayCategory.LIFECYCLE),
    ("subject", DisplayCategory.LIFECYCLE),
    ("consent.", DisplayCategory.ACCESS),
    ("permission.", DisplayCategory.ACCESS),
    ("data.", DisplayCategory.ACCESS),
    ("pii.", DisplayCategory.ACCESS),
    ("session.", DisplayCategory.AUTHENTICATION),
    ("holder.login", DisplayCategory.AUTHENTICATION),
    ("holder.register", DisplayCategory.AUTHENTICATION),
    ("holder.kyc", DisplayCategory.VERIFICATION),
    ("user.profile", DisplayCategory.ADMINISTRATION),
    ("user.", DisplayCategory.AUTHENTICATION),
    ("holder.", DisplayCategory.ADMINISTRATION),
    ("role.", DisplayCategory.ADMINISTRATION),
    ("api_key.", DisplayCategory.ADMINISTRATION),
    ("group.", DisplayCategory.ADMINISTRATION),
    ("issuer.", DisplayCategory.ADMINISTRATION),
    ("tenant.", DisplayCategory.ADMINISTRATION),
    ("template.", DisplayCategory.ADMINISTRATION),
    ("configuration.", DisplayCategory.ADMINISTRATION),
    ("webhook.", DisplayCategory.INTEGRATION),
    ("external_api.", DisplayCategory.INTEGRATION),
    ("digilocker.", DisplayCategory.INTEGRATION),
    ("surepass.", DisplayCategory.VERIFICATION),
    ("audit_log.", DisplayCategory.AUDIT),
)

#: Action spellings this platform emits that the taxonomy above does not name.
#:
#: A chip filters on a closed list built from `_ACTION_CATEGORY`, so an action
#: missing from that table is never pulled into a chip - even when the Category
#: column already labels it correctly by prefix. That is how the Issuance chip
#: came back empty over a log full of issuances: the emitting backend writes
#: `credential.issued`, while the enum above names `credential.issue`. They are
#: the same activity to anyone reading the screen.
#:
#: Listed explicitly rather than resolved by prefix, for the reason
#: `FilterPreset.actions` gives: a prefix query would also sweep in a future
#: `credential.issue_draft` that nobody has classified, and on an audit screen a
#: chip that quietly widens is worse than one that misses.
_CATEGORY_ACTION_ALIASES: Final[dict[DisplayCategory, tuple[str, ...]]] = {
    DisplayCategory.ISSUANCE: ("credential.issued", "credential.reissued"),
    DisplayCategory.VERIFICATION: ("verify.event",),
    DisplayCategory.REVOCATION: ("credential.revoked", "credential.suspended"),
    DisplayCategory.APPROVAL: (
        "request.approved",
        "request.rejected",
        "request.sent",
    ),
}

#: Flattened for `display_category`, so an alias is labelled by the same
#: category that filters on it - the invariant the chip rests on.
_ALIAS_CATEGORY: Final[dict[str, DisplayCategory]] = {
    action: category for category, actions in _CATEGORY_ACTION_ALIASES.items() for action in actions
}

#: Inverted `_ACTION_CATEGORY`, so a chip and a column label share one source.
#:
#: `str(action)` rather than the `Action` member itself: these values are handed
#: to the query builder and go straight into the search DSL, where the store's
#: serialiser sees a plain string rather than an enum it has no rule for. The
#: two compare equal - `Action` is a `StrEnum` - so this only pins the type.
_CATEGORY_ACTIONS: Final[dict[DisplayCategory, tuple[str, ...]]] = {
    category: tuple(
        sorted(
            {str(action) for action, mapped in _ACTION_CATEGORY.items() if mapped is category}
            | set(_CATEGORY_ACTION_ALIASES.get(category, ()))
        )
    )
    for category in DisplayCategory
}

#: Which display category each chip selects. `ALL` and `CRITICAL` are absent:
#: they do not filter by activity at all.
_PRESET_CATEGORY: Final[dict[FilterPreset, DisplayCategory]] = {
    FilterPreset.REVOCATION: DisplayCategory.REVOCATION,
    FilterPreset.APPROVAL: DisplayCategory.APPROVAL,
    FilterPreset.ISSUANCE: DisplayCategory.ISSUANCE,
    FilterPreset.VERIFICATION: DisplayCategory.VERIFICATION,
}

_SEVERITY_TIER: Final[dict[Severity, SeverityTier]] = {
    Severity.INFO: SeverityTier.INFO,
    Severity.LOW: SeverityTier.INFO,
    Severity.MEDIUM: SeverityTier.WARN,
    Severity.HIGH: SeverityTier.WARN,
    Severity.CRITICAL: SeverityTier.CRITICAL,
}


def display_category(action: str) -> DisplayCategory:
    """The Category column value for an action.

    Exact match first, then longest-prefix, then `OTHER`. An action this build
    does not know still gets a sensible label, because the alternative - a
    table full of "other" after an emitter ships a new verb - makes the column
    useless exactly when someone is investigating something new.
    """
    exact = _ACTION_CATEGORY.get(action)
    if exact is not None:
        return exact
    # Before the prefix table: `credential.reissued` would fall to LIFECYCLE on
    # `credential.` and `verify.event` to OTHER, neither of which is the chip
    # that now selects them.
    aliased = _ALIAS_CATEGORY.get(action)
    if aliased is not None:
        return aliased
    for prefix, category in _PREFIX_CATEGORY:
        if action.startswith(prefix):
            return category
    return DisplayCategory.OTHER


def severity_tier(severity: str | None) -> SeverityTier:
    """Collapse a stored severity onto the badge the console draws.

    An unrecognised value reads as INFO rather than raising: a row with an
    odd severity should still appear in the table, and hiding it behind a 500
    would lose the very evidence someone came to look at.
    """
    if not severity:
        return SeverityTier.INFO
    try:
        return _SEVERITY_TIER[Severity(severity)]
    except ValueError:
        return SeverityTier.INFO


# ---------------------------------------------------------------------------
# Row titles
# ---------------------------------------------------------------------------
#: Actions whose generated title reads badly enough to be worth writing out.
#: Everything else goes through `_humanise`, so an action added later still
#: gets a decent title without an entry here.
_ACTION_TITLE: Final[dict[str, str]] = {
    Action.USER_LOGIN: "Signed in",
    Action.USER_LOGOUT: "Signed out",
    Action.USER_LOGIN_FAILED: "Sign-in failed",
    Action.USER_PASSWORD_FORGOT: "Password reset requested",
    Action.HOLDER_LOGIN: "Holder signed in",
    Action.SESSION_SELF_LOGOUT: "Session ended by the user",
    Action.SESSION_LOGOUT_ALL: "All sessions signed out",
    Action.SESSION_SUSPICIOUS_LOGIN: "Suspicious sign-in",
    Action.REQUEST_MOVE_TO_DRAFT: "Request moved back to draft",
    Action.AUDIT_CROSS_USER_ACCESS: "Cross-user audit access",
    Action.DIGILOCKER_PULL: "DigiLocker document pulled",
    Action.DATA_BULK_READ: "Bulk data read",
    Action.UNKNOWN: "Unclassified event",
}

#: Past tense that the "+ed" rule gets wrong.
_IRREGULAR_PAST: Final[dict[str, str]] = {
    "send": "sent",
    "reset": "reset",
    "read": "read",
    "put": "put",
    "set": "set",
    "split": "split",
    "forgot": "forgotten",
    "login": "signed in",
    "logout": "signed out",
    "unsuspend": "reinstated",
    "revoke": "revoked",
}

#: Rendered upper-case wherever they appear in a title.
_ACRONYMS: Final[frozenset[str]] = frozenset(
    {"api", "kyc", "mfa", "otp", "pii", "ip", "id", "url", "sms", "did", "vc", "soc", "kek", "dek"}
)


def event_title(document: dict[str, Any]) -> str:
    """The Event column: what a reader sees before opening the row.

    The emitter's `message` when there is one - it carries the specifics
    ("Verified - GRANT - Door 3") that no derived label can. Otherwise a title
    generated from the action, which is why "Credential issued" reads the same
    whether or not the emitter wrote a message.

    A message that came back `[PROTECTED]` counts as absent. That marker means
    the caller lacks decrypt rights, and rendering it as the row's headline
    would turn a readable table into a column of placeholders; the generated
    title says at least as much and is not personal data. It also keeps the
    table legible after a crypto-shred, when the message is unreadable forever
    but the structural evidence is retained on purpose.
    """
    message = _plain(document.get("message"))
    if message:
        return message[:MAX_ROW_TITLE_LENGTH]
    return humanise_action(str(_event_field(document, "action") or Action.UNKNOWN))


def humanise_action(action: str) -> str:
    """Turn `credential.issue.bulk` into `Credential issued (bulk)`.

    Table-driven where the rule reads badly, rule-driven everywhere else, so a
    verb this build has never seen still renders as a sentence rather than as a
    dotted identifier.
    """
    written = _ACTION_TITLE.get(action)
    if written:
        return written

    bulk = action.endswith(".bulk")
    stem = action[: -len(".bulk")] if bulk else action

    entity, _, verb_part = stem.partition(".")
    words = _split(entity)
    segments = _split(verb_part)
    if segments:
        # The last underscore segment is the verb; anything before it qualifies
        # the entity. `user.password_reset` -> "User password reset",
        # `holder.kyc_validate` -> "Holder KYC validated".
        words = [*words, *segments[:-1], _past_tense(segments[-1])]

    title = _cased(words)
    return f"{title} (bulk)" if bulk else title


def actor_label(actor: dict[str, Any] | None) -> str:
    """Who acted, as one line for the Actor column.

    A machine actor reads as "System - <service>" rather than as a bare service
    name, because "everycred-backend" in a column of people's names looks like a
    person until you read it twice.
    """
    if not actor:
        return "Unknown"
    name = _plain(actor.get("name"))
    service = _plain(actor.get("service"))
    actor_type = str(actor.get("type") or "")

    if actor_type in (ActorType.SYSTEM, ActorType.SERVICE):
        return f"System · {service}" if service else "System"
    if actor_type == ActorType.ANONYMOUS and not name:
        return "Anonymous"
    return name or service or _plain(actor.get("id")) or _cased(_split(actor_type)) or "Unknown"


def target_label(target: dict[str, Any] | None) -> str:
    """What was acted upon, as one line for the Target column.

    Falls back to the id, then to the entity type. A bulk event with no single
    target reads as its count ("42 credentials"), which is the honest summary
    of a row that stands for many records.
    """
    if not target:
        return "—"
    name = _plain(target.get("name"))
    if name:
        return name

    entity = _cased(_split(str(target.get("type") or "")))
    count = target.get("count")
    identifier = _plain(target.get("id"))
    if identifier:
        return identifier
    if isinstance(count, int) and count > 0:
        plural = entity.lower() if entity else "record"
        return f"{count} {plural}{'' if count == 1 else 's'}"
    return entity or "—"


def short_hash(value: str | None, *, head: int = 4, tail: int = 2) -> str | None:
    """Render a hash the way the console shows it: `#a1f4…e2`.

    Abbreviated for the column, never for verification - the full hash travels
    alongside it in the same row, because an operator comparing an anchor
    against an exported record needs all 64 characters.
    """
    if not value:
        return None
    if len(value) <= head + tail:
        return f"#{value}"
    return f"#{value[:head]}…{value[-tail:]}"


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
def _event_field(document: dict[str, Any], key: str) -> Any:
    event = document.get("event")
    return event.get(key) if isinstance(event, dict) else None


def _plain(value: Any) -> str:
    """A displayable string, or empty for anything that is not one.

    `[PROTECTED]` is treated as empty so a masked field falls through to the
    next candidate rather than becoming the label.
    """
    if not isinstance(value, str):
        return ""
    stripped = value.strip()
    return "" if stripped == PROTECTED_PLACEHOLDER else stripped


def _split(raw: str) -> list[str]:
    return [part for part in raw.replace("-", "_").split("_") if part]


def _cased(words: list[str]) -> str:
    """Sentence case, with acronyms left upper."""
    rendered: list[str] = []
    for index, word in enumerate(words):
        if word.lower() in _ACRONYMS:
            rendered.append(word.upper())
        elif index == 0:
            rendered.append(word[:1].upper() + word[1:].lower())
        else:
            rendered.append(word.lower())
    return " ".join(rendered)


def _past_tense(verb: str) -> str:
    """Past tense of a single verb, good enough for a UI label."""
    lowered = verb.lower()
    if lowered in _IRREGULAR_PAST:
        return _IRREGULAR_PAST[lowered]
    if lowered.endswith("ed"):
        return lowered
    if lowered.endswith("e"):
        return f"{lowered}d"
    if lowered.endswith("y") and len(lowered) > 1 and lowered[-2] not in "aeiou":
        return f"{lowered[:-1]}ied"
    return f"{lowered}ed"
