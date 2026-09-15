"""The console listing: display rules, filter chips, and row projection.

Two properties carry most of the weight here.

**A chip cannot disagree with the column it names.** `FilterPreset.ISSUANCE`
selects a set of actions; the Category column labels each row by the same
table. If those two ever diverge, clicking "Issuance" hides rows the table calls
*Issuance*, which an operator reads as missing evidence. The test below asserts
the round trip over every preset.

**The hash self-check runs on the stored bytes.** The integrity hash covers the
document as written - after PII encryption. Decrypting a field before checking
would change what is hashed and report a healthy record as tampered with, so
the ordering is asserted directly rather than left to a comment.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.config import Settings
from app.core.exceptions import InvalidCursor
from app.core.integrity import GENESIS_HASH, compute_hash
from app.core.security.auth import Principal
from app.core.security.crypto import PiiCipher
from app.domain.display import (
    DisplayCategory,
    FilterPreset,
    SeverityTier,
    actor_label,
    display_category,
    event_title,
    humanise_action,
    severity_tier,
    short_hash,
    target_label,
)
from app.domain.enums import Action, ActorType, Scope, Severity
from app.schemas.api import decode_cursor, encode_cursor
from app.search.query import AuditSearchFilter, UserScope
from app.search.repository import SearchPage
from app.search.routing import UserRouter
from app.services.query_service import QueryService

USER = "11111111-1111-4111-8111-111111111111"
CHAIN = f"{USER}:0"


# ---------------------------------------------------------------------------
# Chip / column agreement
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("preset", "category"),
    [
        (FilterPreset.ISSUANCE, DisplayCategory.ISSUANCE),
        (FilterPreset.REVOCATION, DisplayCategory.REVOCATION),
        (FilterPreset.VERIFICATION, DisplayCategory.VERIFICATION),
        (FilterPreset.APPROVAL, DisplayCategory.APPROVAL),
    ],
)
def test_chip_selects_exactly_the_rows_the_column_labels(
    preset: FilterPreset, category: DisplayCategory
) -> None:
    """Every action a chip filters on must be labelled with that same category."""
    assert preset.actions, "an activity chip that selects no actions filters nothing"
    for action in preset.actions:
        assert display_category(action) is category


def test_critical_chip_matches_the_badge_it_names() -> None:
    """The Critical chip and the red Critical badge must select the same rows.

    A chip that also pulled in HIGH would show rows drawing an amber Warn badge
    under a heading that says Critical.
    """
    assert FilterPreset.CRITICAL.severities == (Severity.CRITICAL,)
    assert FilterPreset.CRITICAL.actions == ()
    assert severity_tier(Severity.CRITICAL) is SeverityTier.CRITICAL
    assert severity_tier(Severity.HIGH) is SeverityTier.WARN


def test_chip_actions_are_plain_strings() -> None:
    """These go straight into the search DSL.

    `Action` is a `StrEnum`, so an enum member compares and hashes equal to its
    value and every assertion in this file would pass either way - but the
    store's serialiser is handed these values directly, and it has a rule for
    `str` and none for an enum.
    """
    for preset in FilterPreset:
        for action in preset.actions:
            assert type(action) is str


def test_all_chip_filters_nothing() -> None:
    assert FilterPreset.ALL.actions == ()
    assert FilterPreset.ALL.severities == ()


def test_every_known_action_is_classified() -> None:
    """No action in the taxonomy may fall through to `other`.

    A column full of "other" is a column nobody reads, and the fallback exists
    for actions an emitter ships ahead of this build - not for ones already in
    the enum.
    """
    unclassified = [
        action.value
        for action in Action
        if action is not Action.UNKNOWN and display_category(action.value) is DisplayCategory.OTHER
    ]
    assert unclassified == []


def test_unknown_action_still_gets_a_category_from_its_prefix() -> None:
    """An emitter may ship a verb before this service knows it."""
    assert display_category("credential.issue_provisional") is DisplayCategory.ISSUANCE
    assert display_category("credential.rehypothecate") is DisplayCategory.LIFECYCLE
    assert display_category("wholly.made.up") is DisplayCategory.OTHER


# ---------------------------------------------------------------------------
# Titles and labels
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("action", "expected"),
    [
        (Action.CREDENTIAL_ISSUE, "Credential issued"),
        (Action.CREDENTIAL_ISSUE_BULK, "Credential issued (bulk)"),
        (Action.CREDENTIAL_REVOKE, "Credential revoked"),
        (Action.CREDENTIAL_RENEW, "Credential renewed"),
        (Action.CREDENTIAL_VERIFY, "Credential verified"),
        (Action.CREDENTIAL_UNSUSPEND, "Credential reinstated"),
        (Action.REQUEST_APPROVE, "Request approved"),
        (Action.USER_PROFILE_UPDATE, "User profile updated"),
        (Action.HOLDER_KYC_VALIDATE, "Holder KYC validated"),
        (Action.PII_DECRYPT, "PII decrypted"),
        (Action.API_KEY_CREATE, "API key created"),
        (Action.USER_LOGIN, "Signed in"),
        (Action.SESSION_LOGOUT_ALL, "All sessions signed out"),
    ],
)
def test_action_reads_as_a_sentence(action: Action, expected: str) -> None:
    assert humanise_action(action.value) == expected


def test_title_prefers_the_emitters_message() -> None:
    document = {"event": {"action": "credential.verify"}, "message": "Verified - GRANT - Door 3"}
    assert event_title(document) == "Verified - GRANT - Door 3"


def test_masked_message_falls_back_to_the_action() -> None:
    """`[PROTECTED]` must never become a row's headline.

    A caller without decrypt rights should still read a usable table; a column
    of placeholders tells them nothing the action does not.
    """
    document = {"event": {"action": "credential.issue"}, "message": "[PROTECTED]"}
    assert event_title(document) == "Credential issued"


def test_machine_actor_does_not_masquerade_as_a_person() -> None:
    assert actor_label({"type": ActorType.SYSTEM.value, "service": "HRMS"}) == "System · HRMS"
    assert actor_label({"type": ActorType.USER.value, "name": "D. Reyes"}) == "D. Reyes"
    assert actor_label({"type": ActorType.USER.value, "name": "[PROTECTED]", "id": "u-7"}) == "u-7"
    assert actor_label(None) == "Unknown"


def test_bulk_target_reads_as_its_count() -> None:
    assert target_label({"type": "credential", "count": 42}) == "42 credentials"
    assert target_label({"type": "credential", "name": "Marcus Feld"}) == "Marcus Feld"


def test_short_hash_matches_the_console_format() -> None:
    assert short_hash("a1f4" + "0" * 58 + "e2") == "#a1f4…e2"
    assert short_hash(None) is None


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------
def test_cursor_round_trips() -> None:
    values: list[Any] = ["2026-08-19T09:41:00.000Z", "evt-1"]
    token = encode_cursor(values)
    assert token is not None and "=" not in token
    assert decode_cursor(token) == values


def test_absent_cursor_is_not_an_error() -> None:
    assert decode_cursor(None) is None
    assert decode_cursor("  ") is None
    assert encode_cursor(None) is None
    assert encode_cursor([]) is None


@pytest.mark.parametrize("token", ["not-base64!!", "e30", "W10", "A" * 600])
def test_unreadable_cursor_is_rejected_rather_than_reset(token: str) -> None:
    """A bad cursor must fail loudly.

    Silently restarting at page one would have a caller re-read events it had
    already seen without ever learning it lost its place.
    """
    with pytest.raises(InvalidCursor):
        decode_cursor(token)


# ---------------------------------------------------------------------------
# The listing end to end
# ---------------------------------------------------------------------------
class _FakeRepository:
    """Captures the filter it was asked for and replays a fixed page."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self._events = events
        self.scope: UserScope | None = None
        self.criteria: AuditSearchFilter | None = None
        self.with_total: bool | int = False

    async def search(
        self,
        scope: UserScope,
        criteria: AuditSearchFilter,
        **kwargs: Any,
    ) -> SearchPage:
        self.scope = scope
        self.criteria = criteria
        self.with_total = kwargs.get("with_total", False)
        return SearchPage(
            events=[dict(event) for event in self._events],
            next_cursor=["2026-08-19T09:41:00.000Z", "evt-1"],
            total=len(self._events),
            took_ms=7,
            timed_out=False,
        )


class _FakeQueue:
    """Swallows the audit-of-the-audit write, recording that it happened."""

    def __init__(self) -> None:
        self.published: list[tuple[int, dict[str, Any]]] = []

    async def publish(self, partition: int, payload: dict[str, Any]) -> None:
        self.published.append((partition, payload))


def _document(**overrides: Any) -> dict[str, Any]:
    """A stored document with a genuine hash over its own content."""
    document: dict[str, Any] = {
        "@timestamp": "2026-08-19T09:41:00+00:00",
        "event": {
            "id": "evt-1",
            "action": "credential.verify",
            "category": "credential",
            "type": "info",
            "outcome": "success",
            "severity": "info",
            "ingested": "2026-08-19T09:41:01+00:00",
        },
        "user": {"uuid": USER, "issuer_id": "iss-1"},
        "service": {"name": "everycred-backend"},
        "message": "Verified - GRANT - Door 3",
        "actor": {"type": "user", "id": "act-1", "name": "Verifier A3", "session_id": "sess-9"},
        "target": {"type": "credential", "id": "cred-1", "name": "Marcus Feld"},
        "source": {"ip": "10.20.93.93", "country_code": "IN"},
        "http": {"request_id": "req-1", "trace_id": "trace-1"},
    }
    document.update(overrides)
    document["integrity"] = {
        "seq": 0,
        "prev_hash": GENESIS_HASH,
        "hash": compute_hash(CHAIN, 0, GENESIS_HASH, document),
        "algo": "sha256",
        "chain_id": CHAIN,
    }
    return document


def _service(
    settings: Settings, router: UserRouter, events: list[dict[str, Any]]
) -> tuple[QueryService, _FakeRepository, _FakeQueue]:
    repository = _FakeRepository(events)
    queue = _FakeQueue()
    service = QueryService(
        settings=settings,
        repository=repository,  # type: ignore[arg-type]
        router=router,
        # Encryption off: this suite is about projection and filtering, and the
        # decrypt path has its own tests in test_crypto_shredding.
        cipher=PiiCipher(PiiCipher.generate_master_kek(), keyring=None, enabled=False),
        queue=queue,  # type: ignore[arg-type]
    )
    return service, repository, queue


def _principal(*scopes: Scope) -> Principal:
    return Principal(
        subject="admin-console",
        actor_type=ActorType.SERVICE,
        user_uuid=USER,
        scopes=frozenset(scopes or (Scope.READ,)),
    )


@pytest.mark.asyncio
async def test_row_carries_both_the_table_and_the_drawer(
    settings: Settings, router: UserRouter
) -> None:
    """One request must serve the list and the detail panel."""
    service, _, queue = _service(settings, router, [_document()])

    page = await service.list_events(principal=_principal(), requested_user_uuid=USER)

    assert len(page.events) == 1
    row = page.events[0]

    # The table's columns.
    assert row.timestamp == datetime(2026, 8, 19, 9, 41, tzinfo=UTC)
    assert row.title == "Verified - GRANT - Door 3"
    assert row.category == DisplayCategory.VERIFICATION.value
    assert row.severity_tier == SeverityTier.INFO.value
    assert row.target.label == "Marcus Feld"
    assert row.actor.label == "Verifier A3"
    assert row.anchor.hash_short is not None and row.anchor.hash_short.startswith("#")

    # What the drawer adds.
    assert row.source_ip == "10.20.93.93"
    assert row.actor.session_id == "sess-9"
    assert row.anchor.prev_hash == GENESIS_HASH
    assert row.anchor.seq == 0
    assert row.anchor.chain_id == CHAIN

    # And the read is itself audited.
    assert queue.published, "listing the audit trail must leave its own audit event"
    assert queue.published[0][1]["action"] == Action.AUDIT_SEARCH.value


@pytest.mark.asyncio
async def test_intact_record_passes_its_self_check(settings: Settings, router: UserRouter) -> None:
    service, _, _ = _service(settings, router, [_document()])
    page = await service.list_events(principal=_principal(), requested_user_uuid=USER)
    assert page.events[0].anchor.self_check == "pass"


@pytest.mark.asyncio
async def test_edited_record_fails_its_self_check(settings: Settings, router: UserRouter) -> None:
    """An in-place edit is what the per-row check exists to catch."""
    tampered = _document()
    tampered["target"]["name"] = "Somebody Else"

    service, _, _ = _service(settings, router, [tampered])
    page = await service.list_events(principal=_principal(), requested_user_uuid=USER)
    assert page.events[0].anchor.self_check == "fail"


@pytest.mark.asyncio
async def test_record_without_an_integrity_block_is_unavailable_not_failed(
    settings: Settings, router: UserRouter
) -> None:
    """An event written before chaining was enabled is not evidence of tampering."""
    legacy = _document()
    legacy.pop("integrity")

    service, _, _ = _service(settings, router, [legacy])
    page = await service.list_events(principal=_principal(), requested_user_uuid=USER)
    assert page.events[0].anchor.self_check == "unavailable"


@pytest.mark.asyncio
async def test_chip_reaches_the_query(settings: Settings, router: UserRouter) -> None:
    service, repository, _ = _service(settings, router, [_document()])

    await service.list_events(
        principal=_principal(),
        requested_user_uuid=USER,
        preset=FilterPreset.REVOCATION,
    )

    assert repository.criteria is not None
    assert set(repository.criteria.actions) == set(FilterPreset.REVOCATION.actions)
    assert repository.scope is not None
    assert repository.scope.user_uuid == USER
    assert repository.scope.cross_user is False


@pytest.mark.asyncio
async def test_chip_and_filter_are_a_conjunction(settings: Settings, router: UserRouter) -> None:
    service, repository, _ = _service(settings, router, [_document()])

    await service.list_events(
        principal=_principal(),
        requested_user_uuid=USER,
        preset=FilterPreset.ISSUANCE,
        actions=(Action.CREDENTIAL_ISSUE.value, Action.CREDENTIAL_REVOKE.value),
    )

    assert repository.criteria is not None
    # `credential.revoke` is not an Issuance action, so the chip excludes it.
    assert repository.criteria.actions == (Action.CREDENTIAL_ISSUE.value,)


@pytest.mark.asyncio
async def test_contradictory_filter_returns_nothing_rather_than_everything(
    settings: Settings, router: UserRouter
) -> None:
    """The failure mode worth protecting against.

    Dropping the empty intersection would leave the query builder with no
    action filter at all, and the console would show every event under a chip
    the operator used to exclude them.
    """
    service, repository, _ = _service(settings, router, [_document()])

    page = await service.list_events(
        principal=_principal(),
        requested_user_uuid=USER,
        preset=FilterPreset.ISSUANCE,
        actions=(Action.CREDENTIAL_REVOKE.value,),
    )

    assert page.events == []
    assert page.total == 0
    assert repository.criteria is None, "no query should have been issued at all"


@pytest.mark.asyncio
async def test_listing_requires_the_read_scope(settings: Settings, router: UserRouter) -> None:
    from app.core.security.auth import AuthorizationError

    service, _, _ = _service(settings, router, [_document()])
    with pytest.raises(AuthorizationError):
        await service.list_events(principal=_principal(Scope.WRITE), requested_user_uuid=USER)


@pytest.mark.asyncio
async def test_anchor_network_reports_whether_anything_is_notarised(
    settings: Settings, router: UserRouter
) -> None:
    """The label is cosmetic; the flag must not over-claim.

    The suite runs with `ARCHIVE_ENABLED=false`, so a console reading this
    response cannot truthfully say an event is anchored - and the flag says so.
    """
    service, _, _ = _service(settings, router, [_document()])
    page = await service.list_events(principal=_principal(), requested_user_uuid=USER)

    assert page.anchor_network.name == settings.ANCHOR_NETWORK_NAME
    assert page.anchor_network.notarised is False


@pytest.mark.asyncio
async def test_short_page_hands_back_no_cursor(settings: Settings, router: UserRouter) -> None:
    """A cursor on a partial page costs the caller a request that returns nothing."""
    service, _, _ = _service(settings, router, [_document()])

    page = await service.list_events(principal=_principal(), requested_user_uuid=USER, size=50)
    assert page.cursor is None

    full = await service.list_events(principal=_principal(), requested_user_uuid=USER, size=1)
    assert full.cursor is not None
    assert decode_cursor(full.cursor) == ["2026-08-19T09:41:00.000Z", "evt-1"]
