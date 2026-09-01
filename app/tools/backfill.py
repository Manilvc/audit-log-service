"""Historical backfill: legacy Postgres audit rows → ingest API.

The audit service has no SQL dependency by design. Operators export rows from
tenant DBs as NDJSON, then this module maps and posts them.

Each NDJSON line::

    {
      "source": "user_audit_log" | "holder_audit_log" | "session_audit_log",
      "tenant_id": "<uuid>",
      "uuid": "<row uuid or synthetic id>",
      ...source-specific columns...
    }

Idempotency: ``event_id`` is derived from the legacy row id/uuid so a re-run
is safe (ES ``op_type: create`` rejects duplicates).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx

from app.domain.legacy import map_action, map_entity, map_status

_SERVICE_NAME = "everycred-backend-backfill"


def _aware_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return dt.isoformat()
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.isoformat()


def _strip_nones(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_nones(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nones(v) for v in value]
    return value


def map_legacy_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert one exported legacy row into an ``AuditEventIn``-shaped dict."""
    source = str(row.get("source") or "user_audit_log").strip().lower()
    tenant_id = row.get("tenant_id")
    if not tenant_id:
        raise ValueError("tenant_id is required on every backfill row")

    if source == "holder_audit_log":
        return _map_holder(row, tenant_id=str(tenant_id))
    if source == "session_audit_log":
        return _map_session(row, tenant_id=str(tenant_id))
    return _map_user(row, tenant_id=str(tenant_id))


def _map_user(row: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    event_id = str(row.get("uuid") or row.get("event_id") or "")
    if not event_id:
        raise ValueError("user_audit_log row needs uuid")

    action = map_action(str(row.get("action") or "Unknown"))
    entity = map_entity(str(row.get("entity") or "Unknown"))
    outcome = map_status(str(row.get("status") or "Unknown"))

    user_agent = (
        " ".join(part for part in (row.get("browser_name"), row.get("browser_version")) if part)
        or None
    )

    event: dict[str, Any] = {
        "event_id": event_id,
        "action": str(action),
        "tenant_id": tenant_id,
        "outcome": str(outcome),
        "message": row.get("details"),
        "service_name": _SERVICE_NAME,
        "actor": {
            "type": "user",
            "id": str(row["user_uuid"]) if row.get("user_uuid") else None,
            "numeric_id": row.get("user_id"),
        },
        "target": {
            "type": str(entity),
            "id": str(row["issuer_uuid"]) if row.get("issuer_uuid") else None,
            "numeric_id": row.get("issuer_id"),
        },
        "source": {
            "ip": row.get("ip_address"),
            "country_code": (str(row.get("location_country") or "")[:4] or None),
            "city": row.get("location_city"),
            "user_agent": user_agent,
            "device_type": str(row["device"]) if row.get("device") else None,
        },
        "labels": {
            "source_table": "user_audit_log",
            "backfill": True,
        },
    }
    if row.get("record_uuids") is not None:
        event["labels"]["record_uuids"] = str(row["record_uuids"])[:1000]
    ts = _aware_iso(row.get("created_at"))
    if ts:
        event["timestamp"] = ts
    return cast(dict[str, Any], _strip_nones(event))


def _map_holder(row: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    event_id = str(row.get("uuid") or row.get("event_id") or "")
    if not event_id:
        raise ValueError("holder_audit_log row needs uuid")

    event: dict[str, Any] = {
        "event_id": event_id,
        "action": str(map_action(str(row.get("action") or "Unknown"))),
        "tenant_id": tenant_id,
        "outcome": str(map_status(str(row.get("status") or "Unknown"))),
        "message": row.get("details"),
        "service_name": _SERVICE_NAME,
        "actor": {
            "type": "holder",
            "id": str(row["holder_uuid"]) if row.get("holder_uuid") else None,
            "numeric_id": row.get("holder_id"),
        },
        "target": {"type": str(map_entity(str(row.get("entity") or "Holder")))},
        "labels": {"source_table": "holder_audit_log", "backfill": True},
    }
    if row.get("record_uuids") is not None:
        event["labels"]["record_uuids"] = str(row["record_uuids"])[:1000]
    ts = _aware_iso(row.get("created_at"))
    if ts:
        event["timestamp"] = ts
    return cast(dict[str, Any], _strip_nones(event))


def _map_session(row: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    session_uuid = str(row.get("session_uuid") or "")
    event_type = str(row.get("event_type") or row.get("action") or "")
    row_id = row.get("id") or row.get("uuid") or row.get("event_id")
    if not session_uuid or not event_type or row_id is None:
        raise ValueError("session_audit_log row needs session_uuid, event_type, id")

    event_id = str(row.get("event_id") or f"session-{session_uuid}-{event_type}-{row_id}")
    labels: dict[str, Any] = {"source_table": "session_audit_log", "backfill": True}
    if row.get("actor_user_id") is not None:
        labels["actor_user_id"] = row["actor_user_id"]
    if isinstance(row.get("metadata_json"), dict):
        labels.update(row["metadata_json"])

    event: dict[str, Any] = {
        "event_id": event_id,
        "action": str(map_action(event_type)),
        "tenant_id": tenant_id,
        "outcome": "success",
        "service_name": _SERVICE_NAME,
        "actor": {
            "type": "user",
            "numeric_id": row.get("user_id"),
            "session_id": session_uuid,
        },
        "target": {"type": "session", "id": session_uuid},
        "source": {
            "ip": row.get("ip_address"),
            "country_code": (str(row.get("location_country_code") or "")[:4] or None),
        },
        "labels": labels,
    }
    ts = _aware_iso(row.get("created_at"))
    if ts:
        event["timestamp"] = ts
    return cast(dict[str, Any], _strip_nones(event))


def iter_ndjson(path: Path) -> Iterator[dict[str, Any]]:
    """Yield objects from an NDJSON file, skipping blank / comment lines."""
    # utf-8-sig strips a Windows BOM that PowerShell Set-Content may add.
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            yield payload


def chunked(items: list[Any], size: int) -> Iterator[list[Any]]:
    """Yield successive slices of ``items`` with length ≤ ``size``."""
    for index in range(0, len(items), size):
        yield items[index : index + size]


@dataclass
class BackfillStats:
    """Counters returned by ``run_backfill`` for CLI / operator reporting."""

    read: int = 0
    mapped: int = 0
    accepted: int = 0
    rejected: int = 0
    errors: list[str] = field(default_factory=list)


def run_backfill(
    *,
    path: Path,
    base_url: str,
    api_key: str,
    batch_size: int = 100,
    dry_run: bool = False,
    default_tenant: str | None = None,
    timeout: float = 30.0,
) -> BackfillStats:
    """Map NDJSON rows and POST batches to ``/v1/audit/events``."""
    stats = BackfillStats()
    pending: list[dict[str, Any]] = []
    base = base_url.rstrip("/")

    def flush(batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        if dry_run:
            stats.accepted += len(batch)
            return
        # Group by tenant so the header matches every event in the batch.
        by_tenant: dict[str, list[dict[str, Any]]] = {}
        for event in batch:
            by_tenant.setdefault(str(event["tenant_id"]), []).append(event)

        with httpx.Client(timeout=timeout) as client:
            for tenant_id, events in by_tenant.items():
                response = client.post(
                    f"{base}/v1/audit/events",
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "x-audit-tenant-id": tenant_id,
                        "x-service-name": _SERVICE_NAME,
                    },
                    json={"events": events},
                )
                if response.status_code >= 300:
                    stats.errors.append(
                        f"tenant={tenant_id} status={response.status_code} "
                        f"body={response.text[:300]}"
                    )
                    stats.rejected += len(events)
                    continue
                data = response.json().get("data") or {}
                stats.accepted += int(data.get("accepted") or 0)
                stats.rejected += int(data.get("rejected") or 0)
                for err in data.get("errors") or []:
                    stats.errors.append(str(err))

    for row in iter_ndjson(path):
        stats.read += 1
        if default_tenant and not row.get("tenant_id"):
            row = {**row, "tenant_id": default_tenant}
        try:
            pending.append(map_legacy_row(row))
            stats.mapped += 1
        except Exception as exc:
            stats.errors.append(f"row {stats.read}: {exc}")
            stats.rejected += 1
            continue
        if len(pending) >= batch_size:
            flush(pending)
            pending = []

    flush(pending)
    return stats
