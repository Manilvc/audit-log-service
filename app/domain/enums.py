"""Canonical audit taxonomy.

Values follow Elastic Common Schema (ECS) conventions: lowercase, dotted,
stable forever. They are stored as `keyword` in Elasticsearch, so they must
never be renamed once written - a rename would orphan six years of history.

The legacy tables in the main backend (`user_audit_log`, `session_audit_log`,
`holder_audit_log`, `webhook_logs`) use human-readable display strings such as
"Issue Credential (Bulk)". Those are presentation concerns; this module holds
the machine identity. `app.domain.legacy` maps between the two.
"""

from __future__ import annotations

from enum import StrEnum


class EventCategory(StrEnum):
    """ECS `event.category` - the broad bucket an event belongs to.

    Kept small on purpose: categories drive dashboards and ILM decisions, so
    a short closed set stays useful. Detail belongs in `event.action`.
    """

    AUTHENTICATION = "authentication"
    SESSION = "session"
    IAM = "iam"
    CREDENTIAL = "credential"
    RECORD = "record"
    SUBJECT = "subject"
    CONFIGURATION = "configuration"
    INTEGRATION = "integration"
    CONSENT = "consent"
    DATA_ACCESS = "data_access"
    AUDIT = "audit"
    """Audit-of-the-audit: reads and exports of this service (HIPAA 164.312(b))."""


class EventType(StrEnum):
    """ECS `event.type` - the CRUD-ish shape of the event."""

    CREATION = "creation"
    CHANGE = "change"
    DELETION = "deletion"
    ACCESS = "access"
    START = "start"
    END = "end"
    DENIED = "denied"
    INFO = "info"


class Outcome(StrEnum):
    """ECS `event.outcome`.

    A failed action is often *more* interesting than a successful one, so
    failures are first-class rather than being dropped at the call site.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """Triage priority. Maps to syslog-ish levels for SIEM forwarding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActorType(StrEnum):
    """Who performed the action."""

    USER = "user"
    HOLDER = "holder"
    ADMIN = "admin"
    SERVICE = "service"
    """Machine-to-machine call authenticated by x-api-key."""
    SYSTEM = "system"
    """Scheduled job / background worker with no human trigger."""
    ANONYMOUS = "anonymous"
    """Unauthenticated request - still audited, e.g. a failed login."""


class EntityType(StrEnum):
    """What the action was performed on (ECS-ish `target.type`)."""

    USER = "user"
    HOLDER = "holder"
    ISSUER = "issuer"
    GROUP = "group"
    ROLE = "role"
    PERMISSION = "permission"
    SUBJECT = "subject"
    SUBJECT_FIELD = "subject_field"
    REQUEST = "request"
    RECORD = "record"
    CREDENTIAL = "credential"
    TEMPLATE = "template"
    BADGE = "badge"
    API_KEY = "api_key"
    SESSION = "session"
    TENANT = "tenant"
    CONSENT = "consent"
    WEBHOOK = "webhook"
    CONFIGURATION = "configuration"
    AUDIT_LOG = "audit_log"
    UNKNOWN = "unknown"


class Action(StrEnum):
    """ECS `event.action` - the specific verb.

    Naming rule: `<entity>.<verb>` in lowercase dotted form. Bulk variants get
    an explicit `.bulk` suffix so a single event can represent N targets while
    remaining distinguishable from N single events.
    """

    # ----------------------------------------------------------- authentication
    USER_LOGIN = "user.login"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_LOGOUT = "user.logout"
    USER_REGISTER = "user.register"
    # The three below are event names, not credentials. flake8-bandit and
    # bandit both match on a variable name containing PASSWORD. The suppression
    # markers deliberately carry no trailing prose: bandit parses any text after
    # the marker as further test ids and warns about each word.
    USER_PASSWORD_FORGOT = "user.password_forgot"  # nosec B105
    USER_PASSWORD_RESET = "user.password_reset"  # nosec B105
    USER_PASSWORD_CHANGE = "user.password_change"  # nosec B105
    USER_MFA_ENROLL = "user.mfa_enroll"
    USER_MFA_VERIFY = "user.mfa_verify"
    USER_OTP_SEND = "user.otp_send"
    USER_OTP_VERIFY = "user.otp_verify"
    USER_ACCOUNT_LOCKED = "user.account_locked"
    USER_ACCOUNT_UNLOCKED = "user.account_unlocked"
    USER_MOBILE_REGISTER = "user.mobile_register"
    USER_MOBILE_UPDATE = "user.mobile_update"
    USER_IMPERSONATE = "user.impersonate"

    # ------------------------------------------------------------------ session
    SESSION_CREATED = "session.created"
    SESSION_REFRESHED = "session.refreshed"
    SESSION_IDLE_EXPIRED = "session.idle_expired"
    SESSION_ABSOLUTE_EXPIRED = "session.absolute_expired"
    SESSION_FORCE_TERMINATED = "session.force_terminated"
    SESSION_SELF_LOGOUT = "session.self_logout"
    SESSION_LOGOUT_ALL = "session.logout_all"
    SESSION_SUSPICIOUS_LOGIN = "session.suspicious_login"
    SESSION_LIMIT_EVICTED = "session.limit_evicted"
    SESSION_POLICY_UPDATED = "session.policy_updated"

    # ---------------------------------------------------------------------- IAM
    USER_PROFILE_UPDATE = "user.profile_update"
    USER_DELETE = "user.delete"
    ROLE_CREATE = "role.create"
    ROLE_UPDATE = "role.update"
    ROLE_DELETE = "role.delete"
    PERMISSION_GRANT = "permission.grant"
    PERMISSION_REVOKE = "permission.revoke"
    PERMISSION_DENIED = "permission.denied"
    API_KEY_CREATE = "api_key.create"
    API_KEY_REVOKE = "api_key.revoke"
    API_KEY_USED = "api_key.used"
    GROUP_CREATE = "group.create"
    GROUP_UPDATE = "group.update"
    GROUP_DELETE = "group.delete"
    ISSUER_CREATE = "issuer.create"
    ISSUER_UPDATE = "issuer.update"
    ISSUER_DELETE = "issuer.delete"
    ISSUER_ACTIVATE = "issuer.activate"
    ISSUER_DEACTIVATE = "issuer.deactivate"

    # --------------------------------------------------------------- credential
    CREDENTIAL_ISSUE = "credential.issue"
    CREDENTIAL_ISSUE_BULK = "credential.issue.bulk"
    CREDENTIAL_REVOKE = "credential.revoke"
    CREDENTIAL_REVOKE_BULK = "credential.revoke.bulk"
    CREDENTIAL_REISSUE = "credential.reissue"
    CREDENTIAL_SUSPEND = "credential.suspend"
    CREDENTIAL_SHARE = "credential.share"
    CREDENTIAL_SHARE_BULK = "credential.share.bulk"
    CREDENTIAL_VIEW = "credential.view"
    CREDENTIAL_VERIFY = "credential.verify"
    CREDENTIAL_DOWNLOAD = "credential.download"
    CREDENTIAL_SIGN = "credential.sign"
    CREDENTIAL_ANCHOR = "credential.anchor"

    # ------------------------------------------------------------------- record
    RECORD_CREATE = "record.create"
    RECORD_CREATE_BULK = "record.create.bulk"
    RECORD_UPDATE = "record.update"
    RECORD_DELETE = "record.delete"
    RECORD_DELETE_BULK = "record.delete.bulk"
    RECORD_IMPORT = "record.import"
    RECORD_EXPORT = "record.export"
    RECORD_VALIDATE_BULK = "record.validate.bulk"

    # ------------------------------------------------------- subject / request
    SUBJECT_CREATE = "subject.create"
    SUBJECT_UPDATE = "subject.update"
    SUBJECT_DELETE = "subject.delete"
    SUBJECT_FIELD_UPDATE = "subject_field.update"
    REQUEST_CREATE = "request.create"
    REQUEST_UPDATE = "request.update"
    REQUEST_SEND = "request.send"
    REQUEST_DELETE = "request.delete"
    REQUEST_DELETE_BULK = "request.delete.bulk"
    REQUEST_APPROVE = "request.approve"
    REQUEST_REJECT = "request.reject"
    REQUEST_SUBMIT = "request.submit"
    REQUEST_MOVE_TO_DRAFT = "request.move_to_draft"

    # ------------------------------------------------------------------- holder
    HOLDER_REGISTER = "holder.register"
    HOLDER_LOGIN = "holder.login"
    HOLDER_PROFILE_UPDATE = "holder.profile_update"
    HOLDER_DELETE = "holder.delete"
    HOLDER_KYC_VALIDATE = "holder.kyc_validate"
    HOLDER_KYC_COMPLETED = "holder.kyc_completed"

    # ------------------------------------------------------------------ consent
    CONSENT_GRANT = "consent.grant"
    CONSENT_WITHDRAW = "consent.withdraw"
    CONSENT_UPDATE = "consent.update"
    CONSENT_NOTICE_VIEW = "consent.notice_view"

    # ------------------------------------------------------------ configuration
    CONFIG_UPDATE = "configuration.update"
    TENANT_CREATE = "tenant.create"
    TENANT_UPDATE = "tenant.update"
    TENANT_SUSPEND = "tenant.suspend"
    TEMPLATE_CREATE = "template.create"
    TEMPLATE_UPDATE = "template.update"
    TEMPLATE_DELETE = "template.delete"

    # -------------------------------------------------------------- integration
    WEBHOOK_SEND = "webhook.send"
    WEBHOOK_RECEIVE = "webhook.receive"
    EXTERNAL_API_CALL = "external_api.call"
    DIGILOCKER_PULL = "digilocker.pull"
    SUREPASS_VERIFY = "surepass.verify"

    # -------------------------------------------------------------- data access
    DATA_EXPORT = "data.export"
    DATA_BULK_READ = "data.bulk_read"
    PII_DECRYPT = "pii.decrypt"

    # ----------------------------------------- audit-of-the-audit (HIPAA/SOC 2)
    AUDIT_SEARCH = "audit_log.search"
    AUDIT_EXPORT = "audit_log.export"
    AUDIT_INTEGRITY_VERIFY = "audit_log.integrity_verify"
    AUDIT_ERASURE_REQUEST = "audit_log.erasure_request"
    AUDIT_CROSS_TENANT_ACCESS = "audit_log.cross_tenant_access"

    UNKNOWN = "unknown"


class Scope(StrEnum):
    """OAuth-style scopes this service authorises against.

    Deliberately finer-grained than the main backend's single
    `require_permission` string, because reading audit logs, exporting them and
    erasing personal data inside them carry very different risk.
    """

    READ = "audit:read"
    WRITE = "audit:write"
    EXPORT = "audit:export"
    ERASE = "audit:erase"
    VERIFY = "audit:verify"
    ADMIN = "audit:admin"
    CROSS_TENANT = "audit:cross_tenant"
    """Query across tenant boundaries. Break-glass only; always self-audited."""


# ---------------------------------------------------------------------------
# Severity defaults
# ---------------------------------------------------------------------------
# Emitters may override, but a sensible floor means an emitter that forgets to
# set severity still produces triageable data. Anything security-relevant is
# raised above INFO here rather than relying on every call site to remember.
DEFAULT_SEVERITY: dict[Action, Severity] = {
    Action.USER_LOGIN_FAILED: Severity.MEDIUM,
    Action.USER_ACCOUNT_LOCKED: Severity.HIGH,
    Action.USER_IMPERSONATE: Severity.HIGH,
    Action.SESSION_SUSPICIOUS_LOGIN: Severity.HIGH,
    Action.SESSION_FORCE_TERMINATED: Severity.MEDIUM,
    Action.PERMISSION_DENIED: Severity.MEDIUM,
    Action.PERMISSION_GRANT: Severity.HIGH,
    Action.PERMISSION_REVOKE: Severity.MEDIUM,
    Action.ROLE_UPDATE: Severity.HIGH,
    Action.API_KEY_CREATE: Severity.HIGH,
    Action.API_KEY_REVOKE: Severity.MEDIUM,
    Action.CREDENTIAL_REVOKE: Severity.MEDIUM,
    Action.CREDENTIAL_REVOKE_BULK: Severity.HIGH,
    Action.CREDENTIAL_SIGN: Severity.MEDIUM,
    Action.RECORD_DELETE_BULK: Severity.HIGH,
    Action.REQUEST_DELETE_BULK: Severity.HIGH,
    Action.TENANT_SUSPEND: Severity.CRITICAL,
    Action.CONFIG_UPDATE: Severity.MEDIUM,
    Action.PII_DECRYPT: Severity.HIGH,
    Action.DATA_EXPORT: Severity.HIGH,
    Action.CONSENT_WITHDRAW: Severity.MEDIUM,
    Action.AUDIT_EXPORT: Severity.HIGH,
    Action.AUDIT_ERASURE_REQUEST: Severity.CRITICAL,
    Action.AUDIT_CROSS_TENANT_ACCESS: Severity.CRITICAL,
}

# Category inferred from the action prefix when the emitter omits it. Keeps the
# ingest contract forgiving without letting `event.category` go null, which
# would break every dashboard aggregation.
_ACTION_PREFIX_CATEGORY: tuple[tuple[str, EventCategory], ...] = (
    ("session.", EventCategory.SESSION),
    ("audit_log.", EventCategory.AUDIT),
    ("credential.", EventCategory.CREDENTIAL),
    ("record.", EventCategory.RECORD),
    ("subject", EventCategory.SUBJECT),
    ("request.", EventCategory.SUBJECT),
    ("consent.", EventCategory.CONSENT),
    ("holder.login", EventCategory.AUTHENTICATION),
    ("holder.register", EventCategory.AUTHENTICATION),
    ("holder.", EventCategory.IAM),
    ("role.", EventCategory.IAM),
    ("permission.", EventCategory.IAM),
    ("api_key.", EventCategory.IAM),
    ("group.", EventCategory.IAM),
    ("issuer.", EventCategory.IAM),
    ("tenant.", EventCategory.CONFIGURATION),
    ("template.", EventCategory.CONFIGURATION),
    ("configuration.", EventCategory.CONFIGURATION),
    ("webhook.", EventCategory.INTEGRATION),
    ("external_api.", EventCategory.INTEGRATION),
    ("digilocker.", EventCategory.INTEGRATION),
    ("surepass.", EventCategory.INTEGRATION),
    ("data.", EventCategory.DATA_ACCESS),
    ("pii.", EventCategory.DATA_ACCESS),
    ("user.", EventCategory.AUTHENTICATION),
)

# Auth-category actions that are really IAM mutations, not authentication.
_IAM_USER_ACTIONS = frozenset(
    {
        Action.USER_PROFILE_UPDATE,
        Action.USER_DELETE,
    }
)


def infer_category(action: str) -> EventCategory:
    """Best-effort category for an action string.

    Longest-prefix ordering matters: `holder.login` must be tested before the
    generic `holder.` prefix, which is why the table is an ordered tuple rather
    than a dict.
    """
    if action in _IAM_USER_ACTIONS:
        return EventCategory.IAM
    for prefix, category in _ACTION_PREFIX_CATEGORY:
        if action.startswith(prefix):
            return category
    return EventCategory.DATA_ACCESS


def default_severity(action: str, outcome: Outcome) -> Severity:
    """Severity floor for an action, escalated one step on failure.

    A failed privileged operation is a stronger signal than a successful one -
    it is what an intrusion attempt looks like.
    """
    try:
        base = DEFAULT_SEVERITY.get(Action(action), Severity.INFO)
    except ValueError:
        # Unknown action string: emitters may add actions ahead of this enum.
        base = Severity.INFO
    if outcome is not Outcome.FAILURE:
        return base
    ladder = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return ladder[min(ladder.index(base) + 1, len(ladder) - 1)]
