"""Read path: scope resolution, decryption, and the audit-of-the-audit trail.

Three responsibilities, all of them security-relevant:

1. **Turn a principal into a `UserScope`.** This is where "who may see what"
   is decided. A user token with no explicit grant is pinned to its own events;
   cross-user access requires a dedicated scope.
2. **Decrypt PII for display**, and only for a caller that is allowed to see it.
3. **Audit every read.** HIPAA 164.312(b) and SOC 2 CC7.2 both require that
   access to the audit trail is itself logged. A reader who can search without
   leaving a trace defeats the purpose of the log.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from app.core.config import Settings
from app.core.constants import DEFAULT_LISTING_PAGE_SIZE
from app.core.integrity import compute_hash, hashes_equal
from app.core.logging import get_logger
from app.core.security.auth import AuthorizationError, Principal
from app.core.security.crypto import PiiCipher
from app.domain.display import (
    FilterPreset,
    actor_label,
    display_category,
    event_title,
    severity_tier,
    short_hash,
    target_label,
)
from app.domain.enums import Action, EventCategory, EventType, Outcome, Scope, Severity
from app.domain.events import PROTECTED_PLACEHOLDER
from app.queue.stream import IngestQueue
from app.schemas.api import (
    AggregationRequest,
    AnchorNetwork,
    AnchorSelfCheck,
    AuditLogActor,
    AuditLogAnchor,
    AuditLogListResponse,
    AuditLogRow,
    AuditLogTarget,
    ExportRequest,
    SearchRequest,
    SearchResponse,
    encode_cursor,
)
from app.search.query import AuditSearchFilter, UserScope
from app.search.repository import AuditRepository
from app.search.routing import InvalidUserUuidError, UserRouter

logger = get_logger(__name__)

#: Field paths a caller may restrict `_source` to. An allow-list rather than a
#: pass-through so `pii_ct` can never be requested directly.
_ALLOWED_SOURCE_FIELDS = frozenset(
    {
        "@timestamp",
        "event",
        "event.id",
        "event.action",
        "event.category",
        "event.type",
        "event.outcome",
        "event.severity",
        "event.reason",
        "user",
        "user.uuid",
        "user.issuer_id",
        "actor",
        "actor.id",
        "actor.type",
        "actor.session_id",
        "target",
        "target.id",
        "target.type",
        "source",
        "source.country_code",
        "source.ip_prefix",
        "http",
        "change",
        "labels",
        "service",
        "message",
        "integrity",
    }
)


class QueryService:
    """Serves audit reads."""

    def __init__(
        self,
        *,
        settings: Settings,
        repository: AuditRepository,
        router: UserRouter,
        cipher: PiiCipher,
        queue: IngestQueue,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._router = router
        self._cipher = cipher
        self._queue = queue

    # ------------------------------------------------------------------ scope
    def resolve_scope(
        self,
        principal: Principal,
        *,
        requested_user_uuid: str | None = None,
        cross_user: bool = False,
    ) -> UserScope:
        """Derive the authorised query boundary for a principal.

        The user comes from the `x-audit-user-uuid` header, which the caller
        must send: a service key is not bound to a user, so there is nothing
        else to scope the query by. `principal.user_uuid` holds that same header
        value, captured at authentication time, and serves as the fallback for
        call sites that do not thread the header through separately.

        Raises:
            AuthorizationError: cross-user access was requested without the
                scope.
            InvalidUserUuidError: no user was named on a user-scoped query.
        """
        if cross_user:
            if not principal.has(Scope.CROSS_USER):
                raise AuthorizationError(
                    "cross-user audit access requires the audit:cross_user scope"
                )
            return UserScope(user_uuid=None, cross_user=True)

        user_uuid = requested_user_uuid or principal.user_uuid
        if not user_uuid:
            # 400, not 403: the caller is authenticated and entitled to read -
            # they simply did not say whose trail. Every user-scoped route
            # takes `UserUuidDep` and fails before reaching this, so this is
            # the guard for search and aggregate with `cross_user=false`.
            raise InvalidUserUuidError(
                "name the user you are querying via the x-audit-user-uuid header"
            )

        return UserScope(
            user_uuid=self._router.validate_user_uuid(user_uuid),
            cross_user=False,
        )

    # ----------------------------------------------------------------- search
    async def search(
        self,
        request: SearchRequest,
        *,
        principal: Principal,
        requested_user_uuid: str | None = None,
        cross_user: bool = False,
    ) -> SearchResponse:
        """Run a paginated search and record that it happened."""
        principal.require(Scope.READ)
        scope = self.resolve_scope(
            principal,
            requested_user_uuid=requested_user_uuid,
            cross_user=cross_user,
        )

        page = await self._repository.search(
            scope,
            _to_filter(request),
            size=min(request.size, self._settings.MAX_PAGE_SIZE),
            search_after=request.cursor,
            with_total=(self._settings.TOTAL_HITS_CAP if request.with_total else False),
            source_fields=_validated_fields(request.fields),
        )

        events = await self._reveal(page.events, principal=principal)

        await self.record_access(
            principal=principal,
            scope=scope,
            action=(Action.AUDIT_CROSS_USER_ACCESS if cross_user else Action.AUDIT_SEARCH),
            result_count=len(events),
            detail={
                "size": request.size,
                "paginated": request.cursor is not None,
                "actions_filter": request.actions[:10],
            },
        )

        return SearchResponse(
            events=events,
            # Only hand back a cursor when the page was full; otherwise the
            # caller would make one extra empty request per result set.
            cursor=page.next_cursor if len(page.events) == request.size else None,
            total=page.total,
            took_ms=page.took_ms,
            partial=page.timed_out,
        )

    async def timeline(
        self,
        target_id: str,
        *,
        principal: Principal,
        requested_user_uuid: str | None = None,
        size: int = 200,
        cursor: list[Any] | None = None,
        actions: tuple[str, ...] = (),
    ) -> SearchResponse:
        """Every event about one entity, oldest first, across its whole history.

        Built for the question "what happened to this credential?" - the
        issuance steps, the signing, the anchoring, every later view, share,
        reissue and revocation, in the order they occurred.

        Three differences from `search`, and each one is what makes it a
        timeline rather than a filtered list:

        * **Oldest first.** Steps read in the order they happened.
        * **Whole history, not the default window.** A credential issued eight
          months ago is still the answer to a question asked today.
        * **Matches bulk events too.** A credential issued in a batch records
          its id in `target.ids`, not `target.id`; the filter checks both, so a
          bulk-issued credential is not invisible to its own timeline.

        Still user-scoped: the mandatory user filter applies exactly as it does
        to any other read, so a credential id belonging to another user returns
        an empty timeline rather than its history.
        """
        principal.require(Scope.READ)
        scope = self.resolve_scope(principal, requested_user_uuid=requested_user_uuid)

        page = await self._repository.search(
            scope,
            AuditSearchFilter(target_ids=(target_id,), actions=actions),
            size=min(size, self._settings.MAX_PAGE_SIZE),
            search_after=cursor,
            ascending=True,
            full_history=True,
        )
        events = await self._reveal(page.events, principal=principal)

        await self.record_access(
            principal=principal,
            scope=scope,
            action=Action.AUDIT_SEARCH,
            result_count=len(events),
            detail={"timeline_for": target_id, "size": size},
        )

        return SearchResponse(
            events=events,
            cursor=page.next_cursor if len(page.events) == size else None,
            total=page.total,
            took_ms=page.took_ms,
            partial=page.timed_out,
        )

    # ---------------------------------------------------------------- listing
    async def list_events(
        self,
        *,
        principal: Principal,
        requested_user_uuid: str | None = None,
        preset: FilterPreset = FilterPreset.ALL,
        start: datetime | None = None,
        end: datetime | None = None,
        actions: tuple[str, ...] = (),
        severities: tuple[Severity, ...] = (),
        outcomes: tuple[Outcome, ...] = (),
        actor_ids: tuple[str, ...] = (),
        target_ids: tuple[str, ...] = (),
        issuer_id: str | None = None,
        size: int = DEFAULT_LISTING_PAGE_SIZE,
        cursor: list[Any] | None = None,
        with_total: bool = True,
    ) -> AuditLogListResponse:
        """One page of the audit log table, rendered for display.

        Same query path, same user scope and same audit-of-the-audit trail as
        `search`; what differs is the shape of what comes back. `search` hands
        over raw ECS documents because a SIEM forwarder wants the canonical
        record. This hands over rows: a title, a display category, a badge tier,
        resolved actor and target labels and an abbreviated anchor - the seven
        columns of the table, plus everything the detail drawer shows, so
        opening a row costs no second request.

        Ordering and integrity
        ----------------------
        Newest first, because a console opens on "what just happened".

        Each row carries a hash self-check, recomputed locally from the document
        as read. It is computed *before* PII is decrypted, which is not
        incidental: the hash covers the stored document, and decrypting a field
        would change the bytes it was taken over and turn every row into a false
        `fail`.

        Args:
            preset: the console's filter chip. Narrows the query; never widens
                it, and never displaces the user scope.
            actions / severities: explicit filters, intersected with the
                preset's rather than replacing it, so a chip plus a filter is
                the conjunction the user sees on screen.
            with_total: count matches for the "N events" heading, capped at
                `TOTAL_HITS_CAP`. Costly on a wide window, so a caller paging
                deep can switch it off after the first page.
        """
        principal.require(Scope.READ)
        scope = self.resolve_scope(principal, requested_user_uuid=requested_user_uuid)

        selected_actions = _narrow(actions, preset.actions)
        selected_severities = _narrow(severities, preset.severities)
        if selected_actions is None or selected_severities is None:
            # The chip and the explicit filter have nothing in common, so
            # nothing can match. Answered without a query rather than by
            # dropping one of the two clauses - silently widening a filter on an
            # audit view would show rows the operator believes they excluded.
            await self.record_access(
                principal=principal,
                scope=scope,
                action=Action.AUDIT_SEARCH,
                result_count=0,
                detail={"listing": True, "filter": preset.value, "contradictory_filter": True},
            )
            return self._empty_listing(preset)

        # Clamped once and reused: the "was the page full" test below has to ask
        # about the size actually requested of the store, not the one the caller
        # asked for. Comparing against an unclamped size would never match, so a
        # caller asking for more than MAX_PAGE_SIZE would silently get one page
        # and no cursor to reach the rest.
        page_size = min(size, self._settings.MAX_PAGE_SIZE)
        page = await self._repository.search(
            scope,
            AuditSearchFilter(
                start=start,
                end=end,
                actions=selected_actions,
                severities=selected_severities,
                outcomes=tuple(outcomes),
                actor_ids=tuple(actor_ids),
                target_ids=tuple(target_ids),
                issuer_id=issuer_id,
            ),
            size=page_size,
            search_after=cursor,
            with_total=(self._settings.TOTAL_HITS_CAP if with_total else False),
        )

        # Before `_reveal`: the hash was taken over the stored (encrypted)
        # document, so this has to run on the bytes as they came back.
        checks = [_integrity_self_check(document) for document in page.events]
        revealed = await self._reveal(page.events, principal=principal)
        rows = [
            _to_row(document, self_check=check)
            for document, check in zip(revealed, checks, strict=True)
        ]

        await self.record_access(
            principal=principal,
            scope=scope,
            action=Action.AUDIT_SEARCH,
            result_count=len(rows),
            detail={
                "listing": True,
                "filter": preset.value,
                "size": size,
                "paginated": cursor is not None,
            },
        )

        total = page.total
        return AuditLogListResponse(
            events=rows,
            total=total,
            total_capped=(total is not None and total >= self._settings.TOTAL_HITS_CAP),
            # A cursor only when the page was full. Handing one back on a short
            # page costs the caller an extra request that returns nothing.
            cursor=(encode_cursor(page.next_cursor) if len(page.events) == page_size else None),
            took_ms=page.took_ms,
            partial=page.timed_out,
            filter=preset.value,
            anchor_network=self._anchor_network(),
        )

    def _anchor_network(self) -> AnchorNetwork:
        """The notary this deployment names beneath an event's hash chain.

        `notarised` reports whether WORM checkpointing is actually configured,
        so a deployment that seals nothing cannot have the console claim its
        events are anchored. The label is cosmetic; this flag is the part that
        has to be true.
        """
        return AnchorNetwork(
            name=self._settings.ANCHOR_NETWORK_NAME,
            id=self._settings.ANCHOR_NETWORK_ID or None,
            notarised=bool(self._settings.ARCHIVE_ENABLED and self._settings.ARCHIVE_BUCKET),
        )

    def _empty_listing(self, preset: FilterPreset) -> AuditLogListResponse:
        """A well-formed empty page, so the console renders a table with no rows
        rather than an error."""
        return AuditLogListResponse(
            events=[],
            total=0,
            cursor=None,
            took_ms=0,
            filter=preset.value,
            anchor_network=self._anchor_network(),
        )

    async def get_event(
        self,
        event_id: str,
        *,
        principal: Principal,
        requested_user_uuid: str | None = None,
    ) -> dict[str, Any] | None:
        """Fetch a single event, user-filtered."""
        principal.require(Scope.READ)
        scope = self.resolve_scope(principal, requested_user_uuid=requested_user_uuid)
        document = await self._repository.get_event(scope, event_id)
        if document is None:
            return None
        revealed = await self._reveal([document], principal=principal)
        return revealed[0]

    async def aggregate(
        self,
        request: AggregationRequest,
        *,
        principal: Principal,
        requested_user_uuid: str | None = None,
        cross_user: bool = False,
    ) -> dict[str, Any]:
        """Run a dashboard aggregation.

        `group_by` is already constrained to an allow-list by the schema, so no
        caller-supplied field name reaches the cluster.
        """
        principal.require(Scope.READ)
        scope = self.resolve_scope(
            principal,
            requested_user_uuid=requested_user_uuid,
            cross_user=cross_user,
        )
        aggregations = await self._repository.aggregate(
            scope,
            _to_filter(request),
            group_by=request.group_by,
            interval=request.interval,
            size=request.buckets,
        )
        return aggregations

    # ----------------------------------------------------------------- export
    async def export(
        self,
        request: ExportRequest,
        *,
        principal: Principal,
        requested_user_uuid: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream every matching event over a point-in-time snapshot.

        A generator rather than a list: a million-event export must never be
        assembled in memory. The PIT freezes the view, so events arriving
        mid-export do not turn the extract into a smear across time - which
        would make it useless as evidence.

        The export is audited *before* the first document is yielded, so an
        aborted download still leaves a record that the extract was requested.
        """
        principal.require(Scope.EXPORT)
        scope = self.resolve_scope(principal, requested_user_uuid=requested_user_uuid)
        criteria = _to_filter(request)

        await self.record_access(
            principal=principal,
            scope=scope,
            action=Action.AUDIT_EXPORT,
            result_count=0,
            detail={"max_events": request.max_events, "streaming": True},
        )

        pit_id = await self._repository.open_pit(scope, keep_alive="5m")
        emitted = 0
        cursor: list[Any] | None = None
        try:
            while emitted < request.max_events:
                page = await self._repository.search_pit(
                    scope,
                    criteria,
                    pit_id=pit_id,
                    size=min(self._settings.MAX_PAGE_SIZE, request.max_events - emitted),
                    search_after=cursor,
                )
                if not page.events:
                    break
                revealed = await self._reveal(page.events, principal=principal)
                for document in revealed:
                    if not request.include_integrity:
                        document.pop("integrity", None)
                    yield document
                    emitted += 1
                if page.next_cursor is None or len(page.events) < 1:
                    break
                cursor = page.next_cursor
        finally:
            # Always released: a leaked PIT pins Lucene segments and blocks
            # disk reclamation.
            await self._repository.close_pit(pit_id)
            logger.info(
                "export_completed",
                events=emitted,
                principal=principal.audit_identity,
                user_uuid=scope.user_uuid,
            )

    # ------------------------------------------------------------- decryption
    async def _reveal(
        self, documents: list[dict[str, Any]], *, principal: Principal
    ) -> list[dict[str, Any]]:
        """Decrypt PII for callers permitted to see it.

        A caller without the export or admin scope gets the event structure with
        PII left as ciphertext markers. Most audit review - who did what, when,
        with what outcome - needs no personal data at all, so revealing it by
        default would be an unnecessary standing exposure.
        """
        if not self._cipher.enabled:
            return documents

        may_decrypt = principal.has(Scope.ADMIN) or principal.has(Scope.EXPORT)
        if not may_decrypt:
            return [_mask_ciphertext(document) for document in documents]

        revealed: list[dict[str, Any]] = []
        for document in documents:
            revealed.append(await self._cipher.decrypt_document(document))
        return revealed

    # ------------------------------------------------ audit-of-the-audit trail
    async def record_access(
        self,
        *,
        principal: Principal,
        scope: UserScope,
        action: Action,
        result_count: int,
        detail: dict[str, Any],
    ) -> None:
        """Emit an audit event recording this read.

        Failures are swallowed. This mirrors the main backend's
        `AuditLogService`: a problem writing the meta-audit event must not fail
        the caller's query. The queue is durable, so the realistic failure here
        is Redis being unreachable, which is already alerted on.
        """
        try:
            user_uuid = scope.user_uuid or "cross-user"
            partition = self._router.partition_for(
                user_uuid if scope.user_uuid else "cross-user",
                self._settings.STREAM_PARTITIONS,
            )
            payload = {
                "event_id": None,
                "timestamp": datetime.now(UTC).isoformat(),
                "user_uuid": user_uuid,
                "issuer_id": scope.issuer_id,
                "action": action.value,
                "category": EventCategory.AUDIT.value,
                "type": EventType.ACCESS.value,
                "outcome": Outcome.SUCCESS.value,
                "severity": (
                    Severity.CRITICAL.value
                    if action is Action.AUDIT_CROSS_USER_ACCESS
                    else Severity.INFO.value
                ),
                "actor": {
                    "type": principal.actor_type.value,
                    "id": principal.subject,
                    "on_behalf_of": principal.on_behalf_of,
                    "service": principal.subject if principal.is_service else None,
                },
                "target": {"type": "audit_log", "count": result_count},
                "service_name": self._settings.SERVICE_NAME,
                "labels": {
                    "result_count": result_count,
                    "cross_user": scope.cross_user,
                    "self_restricted": scope.actor_id is not None,
                    **detail,
                },
            }
            # `event_id` is dropped so the worker assigns a fresh one; a None id
            # would otherwise become the ES document id.
            payload.pop("event_id")
            await self._queue.publish(partition, payload)
        except Exception as exc:
            logger.error("audit_of_audit_write_failed", error=str(exc), action=action.value)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _to_filter(request: SearchRequest) -> AuditSearchFilter:
    """Translate the wire request into the internal filter."""
    return AuditSearchFilter(
        start=request.start,
        end=request.end,
        actions=tuple(request.actions),
        categories=tuple(request.categories),
        outcomes=tuple(request.outcomes),
        severities=tuple(request.severities),
        actor_ids=tuple(request.actor_ids),
        actor_types=tuple(actor.value for actor in request.actor_types),
        session_id=request.session_id,
        target_ids=tuple(request.target_ids),
        target_types=tuple(entity.value for entity in request.target_types),
        issuer_id=request.issuer_id,
        service_names=tuple(request.service_names),
        request_id=request.request_id,
        trace_id=request.trace_id,
        event_ids=tuple(request.event_ids),
        ip_prefix=request.ip_prefix,
        country_codes=tuple(request.country_codes),
        http_status_min=request.http_status_min,
        http_status_max=request.http_status_max,
        label_terms=request.label_terms,
        text=request.text,
    )


def _narrow(
    requested: tuple[Any, ...],
    preset: tuple[Any, ...],
) -> tuple[Any, ...] | None:
    """Intersect an explicit filter with a chip's, or None when they conflict.

    Three cases, and the third is the one that matters. With only one of the
    two supplied, that one applies. With both, the answer is the intersection -
    a chip and a filter shown together on screen read as "and". When the
    intersection is empty the correct answer is "no rows", which is why this
    returns None rather than an empty tuple: an empty tuple means *no filter*
    to the query builder, so returning one would quietly show everything the
    operator just excluded.
    """
    if not preset:
        return requested
    if not requested:
        return preset
    allowed = set(preset)
    kept = tuple(value for value in requested if value in allowed)
    return kept or None


def _integrity_self_check(document: dict[str, Any]) -> AnchorSelfCheck:
    """Does this record still hash to the value stored on it?

    Detects an in-place edit of a single document at the cost of one SHA-256
    over content already in memory - cheap enough to run on every row.

    It is not a chain verification: deletion, reordering and insertion are
    detected by walking neighbouring sequence numbers, which is what the
    compliance verify endpoint does and what the drawer's "Verify chain" button
    calls. This answers the narrower question the table can afford to ask.

    Must be called on the document as stored, before PII is decrypted: the hash
    was taken over the encrypted bytes, so a decrypted document would never
    match.
    """
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        # No integrity block: written before chaining was enabled, or the
        # caller narrowed `_source` and left it out. Not a failure, and
        # reporting it as one would cry wolf on a legitimately old record.
        return "unavailable"
    try:
        recomputed = compute_hash(
            str(integrity["chain_id"]),
            int(integrity["seq"]),
            str(integrity["prev_hash"]),
            document,
        )
        stored = str(integrity["hash"])
    except (KeyError, TypeError, ValueError):
        return "unavailable"
    return "pass" if hashes_equal(recomputed, stored) else "fail"


def _to_row(document: dict[str, Any], *, self_check: AnchorSelfCheck) -> AuditLogRow:
    """Project one stored document onto a table row."""
    event = _section(document, "event")
    actor = _section(document, "actor")
    target = _section(document, "target")
    source = _section(document, "source")
    http = _section(document, "http")
    integrity = _section(document, "integrity")
    user = _section(document, "user")
    service = _section(document, "service")

    # Each `_visible` call reports whether it hit a mask, so the row can say
    # "there is personal data here you may not see" instead of leaving the
    # console to read a null as "this field was empty".
    protected = False
    actor_name, protected = _visible(actor.get("name"), protected)
    target_name, protected = _visible(target.get("name"), protected)
    source_ip, protected = _visible(source.get("ip"), protected)
    _, protected = _visible(document.get("message"), protected)

    stored_hash = _text(integrity.get("hash"))
    stored_prev = _text(integrity.get("prev_hash"))

    return AuditLogRow(
        event_id=_text(event.get("id")) or "",
        timestamp=document.get("@timestamp"),
        ingested_at=event.get("ingested"),
        title=event_title(document),
        action=_text(event.get("action")) or str(Action.UNKNOWN),
        category=display_category(_text(event.get("action")) or "").value,
        ecs_category=_text(event.get("category")) or None,
        type=_text(event.get("type")) or None,
        outcome=_text(event.get("outcome")) or None,
        severity=_text(event.get("severity")) or None,
        severity_tier=severity_tier(_text(event.get("severity"))).value,
        reason=_text(event.get("reason")) or None,
        actor=AuditLogActor(
            id=_text(actor.get("id")) or None,
            type=_text(actor.get("type")) or None,
            name=actor_name or None,
            service=_text(actor.get("service")) or None,
            session_id=_text(actor.get("session_id")) or None,
            on_behalf_of=_text(actor.get("on_behalf_of")) or None,
            label=actor_label(actor),
        ),
        target=AuditLogTarget(
            id=_text(target.get("id")) or None,
            type=_text(target.get("type")) or None,
            name=target_name or None,
            count=target.get("count") if isinstance(target.get("count"), int) else None,
            label=target_label(target),
        ),
        source_ip=source_ip or None,
        country_code=_text(source.get("country_code")) or None,
        service_name=_text(service.get("name")) or None,
        issuer_id=_text(user.get("issuer_id")) or None,
        request_id=_text(http.get("request_id")) or None,
        trace_id=_text(http.get("trace_id")) or None,
        anchor=AuditLogAnchor(
            seq=integrity.get("seq") if isinstance(integrity.get("seq"), int) else None,
            chain_id=_text(integrity.get("chain_id")) or None,
            algo=_text(integrity.get("algo")) or None,
            hash=stored_hash or None,
            hash_short=short_hash(stored_hash),
            prev_hash=stored_prev or None,
            prev_hash_short=short_hash(stored_prev),
            self_check=self_check,
        ),
        pii_protected=protected,
    )


def _section(document: dict[str, Any], key: str) -> dict[str, Any]:
    """One nested block of the ECS document, or an empty dict.

    The stored shape prunes empty containers (see `AuditEvent.to_document`), so
    a missing `source` or `integrity` block is ordinary rather than an error.
    """
    value = document.get(key)
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _visible(value: Any, protected: bool) -> tuple[str, bool]:
    """Split a possibly-masked PII field into its value and the masked flag.

    Returns the value only when it is genuinely readable; `[PROTECTED]` comes
    back as empty with the flag raised, so the row reports the masking once
    rather than repeating the marker in every field.
    """
    if not isinstance(value, str):
        return "", protected
    stripped = value.strip()
    if stripped == PROTECTED_PLACEHOLDER:
        return "", True
    return stripped, protected


def _validated_fields(fields: list[str] | None) -> list[str] | None:
    """Filter requested `_source` paths against the allow-list.

    Silently dropping an unknown path is preferred to a 400: the caller still
    gets a usable response, and `pii_ct` can never be smuggled in.
    """
    if not fields:
        return None
    allowed = [field for field in fields if field in _ALLOWED_SOURCE_FIELDS]
    return allowed or None


def _mask_ciphertext(document: dict[str, Any]) -> dict[str, Any]:
    """Replace encrypted blobs with a marker for a caller without decrypt rights.

    The marker matters: it tells the reader that personal data exists on this
    event, so they know to request elevated access rather than assuming the
    field was empty.
    """
    ciphertexts = document.pop("pii_ct", None)
    if isinstance(ciphertexts, dict):
        for path in ciphertexts:
            _set_masked(document, path)
    return document


def _set_masked(document: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    node = document
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = PROTECTED_PLACEHOLDER
