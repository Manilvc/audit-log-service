"""Map legacy main-backend audit strings ↔ ECS taxonomy.

The Postgres tables (`user_audit_log`, `holder_audit_log`, `session_audit_log`)
store human-readable display strings such as ``"Issue Credential (Bulk)"``.
Emitters dual-writing into this service, and any historical backfill, need a
stable bridge so call sites do not have to be rewritten in one shot.

Lookup is by the *value* stored in the DB (not the Python enum member name),
because that is what Celery payloads and serializers already carry.
"""

from __future__ import annotations

from app.domain.enums import Action, EntityType, EventCategory, Outcome, infer_category

# ---------------------------------------------------------------------------
# ActionType → Action  (user_audit_log / activity_logger)
# ---------------------------------------------------------------------------
LEGACY_ACTION_TO_ECS: dict[str, Action] = {
    # User
    "Login": Action.USER_LOGIN,
    "Logout": Action.USER_LOGOUT,
    "Register": Action.USER_REGISTER,
    "Update Profile": Action.USER_PROFILE_UPDATE,
    "Forgot Password": Action.USER_PASSWORD_FORGOT,
    "Reset Password": Action.USER_PASSWORD_RESET,
    "Register Mobile": Action.USER_MOBILE_REGISTER,
    "Update Mobile": Action.USER_MOBILE_UPDATE,
    "Send OTP": Action.USER_OTP_SEND,
    "Verify OTP": Action.USER_OTP_VERIFY,
    "Account Locked": Action.USER_ACCOUNT_LOCKED,
    # Authority — closest machine identity is tenant.* (no authority.* action)
    "Create Authority": Action.TENANT_CREATE,
    "Update Authority": Action.TENANT_UPDATE,
    # Issuer
    "Create Issuer Profile": Action.ISSUER_CREATE,
    "Update Issuer Profile": Action.ISSUER_UPDATE,
    "Delete Issuer Profile": Action.ISSUER_DELETE,
    "Activate Issuer Profile": Action.ISSUER_ACTIVATE,
    # Group
    "Create Group": Action.GROUP_CREATE,
    "Update Group": Action.GROUP_UPDATE,
    "Delete Group": Action.GROUP_DELETE,
    # Subject
    "Create Subject": Action.SUBJECT_CREATE,
    "Update Subject": Action.SUBJECT_UPDATE,
    "Delete Subject": Action.SUBJECT_DELETE,
    # Request
    "Make Request": Action.REQUEST_CREATE,
    "Update Request": Action.REQUEST_UPDATE,
    "Send Request": Action.REQUEST_SEND,
    "Delete Request": Action.REQUEST_DELETE,
    "Delete Request (Bulk)": Action.REQUEST_DELETE_BULK,
    "Reject Request": Action.REQUEST_REJECT,
    "Approve Request": Action.REQUEST_APPROVE,
    "Move To Draft": Action.REQUEST_MOVE_TO_DRAFT,
    # Record
    "Create Record": Action.RECORD_CREATE,
    "Create Record (Bulk)": Action.RECORD_CREATE_BULK,
    "Update Record": Action.RECORD_UPDATE,
    "Delete Record": Action.RECORD_DELETE,
    "Delete Record (Bulk)": Action.RECORD_DELETE_BULK,
    "Delete Bulk Upload Preview": Action.RECORD_DELETE_BULK,
    "Upload Image (Bulk)": Action.RECORD_IMPORT,
    "Validate Record (Bulk)": Action.RECORD_VALIDATE_BULK,
    # Credential
    "Issue Credential": Action.CREDENTIAL_ISSUE,
    "Issue Credential (Bulk)": Action.CREDENTIAL_ISSUE_BULK,
    "Revoke Credential": Action.CREDENTIAL_REVOKE,
    "Revoke Credential (Bulk)": Action.CREDENTIAL_REVOKE_BULK,
    "Reissue Credential": Action.CREDENTIAL_REISSUE,
    "Share Credential": Action.CREDENTIAL_SHARE,
    "Share Credential (Bulk)": Action.CREDENTIAL_SHARE_BULK,
    "View Credential": Action.CREDENTIAL_VIEW,
    "Preview Field": Action.PII_DECRYPT,
    "Unknown": Action.UNKNOWN,
}

# ---------------------------------------------------------------------------
# HolderActionType → Action  (holder_audit_log)
# ---------------------------------------------------------------------------
LEGACY_HOLDER_ACTION_TO_ECS: dict[str, Action] = {
    "Holder Request Submit": Action.REQUEST_SUBMIT,
    "Holder Register": Action.HOLDER_REGISTER,
    "Holder Login": Action.HOLDER_LOGIN,
    "Update Holder Profile": Action.HOLDER_PROFILE_UPDATE,
    "Change Password": Action.USER_PASSWORD_CHANGE,
    "Holder Request Decline": Action.REQUEST_REJECT,
    "Holder Request Approve": Action.REQUEST_APPROVE,
    "Request Declined By Issuer": Action.REQUEST_REJECT,
    "Request Approved By Issuer": Action.REQUEST_APPROVE,
    "Holder Delete": Action.HOLDER_DELETE,
    "Holder KYC Validate": Action.HOLDER_KYC_VALIDATE,
    "KYC Status Completed": Action.HOLDER_KYC_COMPLETED,
    "Unknown": Action.UNKNOWN,
}

# ---------------------------------------------------------------------------
# SessionEventType → Action  (session_audit_log)
# ---------------------------------------------------------------------------
LEGACY_SESSION_EVENT_TO_ECS: dict[str, Action] = {
    "CREATED": Action.SESSION_CREATED,
    "REFRESHED": Action.SESSION_REFRESHED,
    "IDLE_EXPIRED": Action.SESSION_IDLE_EXPIRED,
    "ABSOLUTE_EXPIRED": Action.SESSION_ABSOLUTE_EXPIRED,
    "FORCE_TERMINATED": Action.SESSION_FORCE_TERMINATED,
    "SELF_LOGOUT": Action.SESSION_SELF_LOGOUT,
    "LOGOUT_ALL": Action.SESSION_LOGOUT_ALL,
    "SUSPICIOUS_LOGIN": Action.SESSION_SUSPICIOUS_LOGIN,
    "LIMIT_EVICTED": Action.SESSION_LIMIT_EVICTED,
    "POLICY_UPDATED": Action.SESSION_POLICY_UPDATED,
}

# ---------------------------------------------------------------------------
# EntityType display strings → EntityType
# ---------------------------------------------------------------------------
LEGACY_ENTITY_TO_ECS: dict[str, EntityType] = {
    "User": EntityType.USER,
    "Issuer": EntityType.ISSUER,
    "Group": EntityType.GROUP,
    "Subject": EntityType.SUBJECT,
    "Request": EntityType.REQUEST,
    "Record": EntityType.RECORD,
    "Credential": EntityType.CREDENTIAL,
    "Holder": EntityType.HOLDER,
    "Unknown": EntityType.UNKNOWN,
}

# ---------------------------------------------------------------------------
# ActionStatus → Outcome
# ---------------------------------------------------------------------------
LEGACY_STATUS_TO_OUTCOME: dict[str, Outcome] = {
    "Success": Outcome.SUCCESS,
    "Failure": Outcome.FAILURE,
    "Failed": Outcome.FAILURE,
}

# Reverse maps for display / migration tooling. When several legacy strings
# collapse onto one Action, keep the first (canonical) display string.
_ECS_TO_LEGACY_ACTION: dict[Action, str] = {}
for _legacy, _action in LEGACY_ACTION_TO_ECS.items():
    _ECS_TO_LEGACY_ACTION.setdefault(_action, _legacy)
for _legacy, _action in LEGACY_HOLDER_ACTION_TO_ECS.items():
    _ECS_TO_LEGACY_ACTION.setdefault(_action, _legacy)
for _legacy, _action in LEGACY_SESSION_EVENT_TO_ECS.items():
    _ECS_TO_LEGACY_ACTION.setdefault(_action, _legacy)


def map_action(legacy: str) -> Action:
    """Map a legacy action / session-event string to an ECS ``Action``.

    Accepts user-audit display strings, holder-audit display strings, and
    session event codes. Unknown input returns ``Action.UNKNOWN`` rather than
    raising, so a dual-write path never fails the caller's business flow.
    """
    if legacy in LEGACY_ACTION_TO_ECS:
        return LEGACY_ACTION_TO_ECS[legacy]
    if legacy in LEGACY_HOLDER_ACTION_TO_ECS:
        return LEGACY_HOLDER_ACTION_TO_ECS[legacy]
    if legacy in LEGACY_SESSION_EVENT_TO_ECS:
        return LEGACY_SESSION_EVENT_TO_ECS[legacy]
    # Already an ECS action string (emitter migrated ahead of the call site).
    try:
        return Action(legacy)
    except ValueError:
        return Action.UNKNOWN


def map_entity(legacy: str) -> EntityType:
    """Map a legacy entity display string to ``EntityType``."""
    if legacy in LEGACY_ENTITY_TO_ECS:
        return LEGACY_ENTITY_TO_ECS[legacy]
    try:
        return EntityType(legacy.lower())
    except ValueError:
        return EntityType.UNKNOWN


def map_status(legacy: str) -> Outcome:
    """Map a legacy ``ActionStatus`` display string to ``Outcome``."""
    if legacy in LEGACY_STATUS_TO_OUTCOME:
        return LEGACY_STATUS_TO_OUTCOME[legacy]
    lowered = legacy.strip().lower()
    if lowered in {"success", "ok"}:
        return Outcome.SUCCESS
    if lowered in {"failure", "failed", "error"}:
        return Outcome.FAILURE
    return Outcome.UNKNOWN


def to_legacy_action(action: Action | str) -> str:
    """Best-effort reverse: ECS action → canonical legacy display string.

    Useful for UI that still renders the old labels during cutover. Returns the
    ECS string itself when no legacy label exists.
    """
    try:
        ecs = action if isinstance(action, Action) else Action(action)
    except ValueError:
        return str(action)
    return _ECS_TO_LEGACY_ACTION.get(ecs, str(ecs))


def legacy_event_hints(legacy_action: str) -> tuple[Action, EventCategory]:
    """Return ``(action, inferred category)`` for a legacy action string.

    Convenience for emitters that only have the old display string and need
    both fields for an ingest payload.
    """
    action = map_action(legacy_action)
    return action, infer_category(action)
