# EveryCRED Audit Log Service

Tamper-evident, multi-tenant audit logging for the EveryCRED DCS platform.

Every security-relevant action across the platform — credential issuance,
revocation, login, permission change, consent withdrawal, configuration edit —
lands here as one canonical event, in one queryable place, with cryptographic
proof it has not been altered.

---

## Why this exists

Audit records were spread across four tables in the main backend, each with its
own shape and its own idea of what an "audit log" is:

| Table | Location |
|---|---|
| `session_audit_log` | `apps/v1/api/sessions/` |
| `user_audit_log`, `user_activity_log`, `holder_audit_log` | `apps/v1/api/activity_logger/` |
| `webhook_logs` | `apps/v1/api/external_api_log/` |

That works until an auditor asks a cross-cutting question — *"show me everything
this user did last March"* — which needs four joins across two schemas, per
tenant, with no guarantee a row was never quietly `UPDATE`d. This service
replaces them with one event model, one index, and an integrity guarantee.

## What it guarantees

| Property | Mechanism |
|---|---|
| **No lost events** | Redis Streams buffer with explicit ack; nothing is acknowledged until it is in both Elasticsearch and the WORM archive |
| **No duplicate events** | `op_type: create` keyed on the event id — exactly-once on top of an at-least-once queue |
| **Modification detected** | SHA-256 hash chain per (tenant, partition) |
| **Deletion / reordering detected** | Gap-free sequence numbers + `prev_hash` links |
| **Wholesale rewrite detected** | Chain heads notarised into S3 Object Lock (COMPLIANCE mode) |
| **Tenant isolation** | Mandatory filter injected in the query layer, plus `constant_keyword` enforcement on dedicated streams |
| **Right to erasure** | Crypto-shredding — destroy the subject's key, keep the record |

---

## Architecture

```
emitting services (everycred-backend, consent, contributor, verifier, signer)
        │  POST /v1/audit/events        x-api-key + x-audit-tenant-id
        ▼
┌──────────────────┐
│   Audit API      │  validate → resolve tenant → enqueue.  Returns 202 fast:
│   (FastAPI)      │  no crypto, no ES, no S3 on the caller's request path.
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Redis Streams   │  durable buffer, N partitions, tenant pinned to one
│  (appendonly)    │  partition so its hash chain stays totally ordered
└────────┬─────────┘
         ▼
┌──────────────────┐   1. encrypt PII per data subject
│  Ingest Worker   │   2. reserve seq + chain hash (atomic, single writer)
│  (own process)   │   3. bulk index to Elasticsearch
└───┬──────────┬───┘   4. seal segment to S3 WORM
    │          │       5. commit chain head → 6. ack
    ▼          ▼
┌─────────┐  ┌──────────────────┐
│  ES 9.x │  │  S3 Object Lock  │
│  data   │  │  COMPLIANCE mode │  immutable even to the account root
│ streams │  │  segments +      │
└─────────┘  │  checkpoints     │
             └──────────────────┘
```

### Tenant isolation — hybrid

The platform is **database-per-tenant** (`core/tenant/` in the main backend), so
the index layer mirrors that shape without paying for one index per customer:

- **Shared data stream** (`audit-shared`) by default. Every document is routed
  by `tenant.id`, so a tenant's search hits **one shard** rather than fanning
  out across all of them.
- **Dedicated data stream** (`audit-t-<tenant>`) for high-volume or
  contractually-isolated tenants. Here `tenant.id` is mapped as
  `constant_keyword`, so a backing index adopts the tenant id of its first
  document and **Elasticsearch itself rejects** any document carrying a
  different one. Cross-tenant contamination becomes impossible rather than
  merely unlikely.
- Promotion is non-destructive: reads cover the dedicated stream *and* the
  shared one, so history written before promotion stays visible.

Because the cluster runs the **Basic licence**, there is no document-level
security to fall back on. Isolation is therefore a code invariant:
`app/search/query.py` is the only place a query is built, it takes a
`TenantScope`, and there is no path that omits the tenant filter.
`tests/unit/test_tenant_isolation.py` asserts this over every filter
permutation.

### Tamper evidence

For sequence *n* in a chain:

```
hash_n = SHA256( chain_id ‖ seq_n ‖ hash_{n-1} ‖ canonical_json(doc_n) )
```

Each component is length-prefixed, so no boundary-shifting forgery is possible.
The hash is computed over the document **after** PII encryption — which is what
lets a crypto-shred years later destroy personal data without invalidating the
chain.

Three attacks, each distinguishable in the verification report:

| Break kind | Means |
|---|---|
| `hash_mismatch` | a stored record was modified in place |
| `gap` / `duplicate_seq` | records were deleted or replayed |
| `prev_mismatch` | records were reordered or inserted |

A self-consistent chain only proves nobody edited a single record. The
periodically sealed **checkpoint** in S3 Object Lock is what closes the
rewrite-the-whole-tail hole: it is immutable even to the account root, so a
rewritten chain contradicts an object nobody can change.

### Privacy: crypto-shredding

GDPR Art. 17 and DPDP s.12 grant erasure. SOC 2, ISO 27001 and HIPAA
164.312(b) demand immutability. Read literally, they contradict.

```
PII_MASTER_KEK (env, 32 bytes)
  ├─ HKDF "keyid" → key-id derivation key   (deterministic)
  ├─ HKDF "bidx"  → blind-index key         (optional, off by default)
  └─ AES-GCM wrap → per-subject DEK (random, in the keyring index)
                      └─ AES-256-GCM → PII field ciphertext
```

- PII is **never indexed**. It lives in `pii_ct`, an object mapped
  `enabled: false` — no inverted index, no doc values, not searchable,
  not aggregatable.
- Each field's AAD is `<event_id>|<field_path>`, so a ciphertext lifted into
  another event or field fails authentication rather than silently decrypting to
  someone else's data.
- **Erasure destroys the key, not the record.** Structural evidence — who acted,
  on what, when, with what outcome — survives for the auditor; the personal data
  becomes permanently unreadable. The keyring keeps a *tombstone*, so a reader
  can tell "erased on request" from "never existed".
- `source.ip` is replaced by a truncated `source.ip_prefix` (/24, /48) in the
  clear for network analytics, with the full address encrypted.

Search is by stable non-PII identifiers (`actor.id`, `target.id`, `session_id`),
which is what a DSR or an investigation actually starts from.

---

## Setup

Requires **Python 3.13+** (development targets 3.14), `uv`, and Docker.

**Full walkthrough (Windows notes, dual-write, smoke, troubleshooting):**
[docs/SETUP.md](docs/SETUP.md).

```bash
# 1. install uv (once)
curl -LsSf https://astral.sh/uv/install.sh | sh     # macOS / Linux
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"   # Windows

# 2. dependencies — uv creates .venv and downloads the interpreter itself
uv sync --all-extras

# 3. secrets
cp .env.example .env
uv run audit-service generate-kek        # → PII_MASTER_KEK
# Local: set INDEX_REPLICAS=0 and ES_VERIFY_CERTS=false in .env

# 4. local infrastructure (Elasticsearch 9 + Redis AOF + MinIO with Object Lock)
docker compose up -d elasticsearch redis minio
./scripts/init-minio.sh                  # creates the WORM bucket (see SETUP.md on Windows)

# 5. cluster topology (idempotent; also runs on startup)
uv run audit-service bootstrap

# 6. run — API and worker are separate processes
uv run audit-service serve
uv run audit-service worker
```

### Commands

| Command | Purpose |
|---|---|
| `serve` | HTTP API |
| `worker` | ingest worker — run at least one, scale independently |
| `bootstrap` | apply ILM policy, index templates, keyring index, data streams |
| `generate-kek` | mint a PII master key |
| `verify --tenant <id>` | integrity check; **exits non-zero on a break**, so it works as a cron/CI gate |
| `backfill --file rows.ndjson` | replay a legacy Postgres export into ingest (idempotent on event id) |

---

## API

Base path `/v1`. Responses use the platform envelope
`{"status", "data", "message"}`, matching
`core/utils/standard_response.py` in the main backend.

| Method | Path | Scope | Notes |
|---|---|---|---|
| `POST` | `/v1/audit/events` | `audit:write` | Batch ingest, ≤500 events. **202**, partial success |
| `POST` | `/v1/audit/events/search` | `audit:read` | Cursor pagination |
| `GET` | `/v1/audit/events/{id}` | `audit:read` | Tenant-filtered |
| `POST` | `/v1/audit/events/aggregate` | `audit:read` | `group_by` allow-list |
| `POST` | `/v1/audit/events/export` | `audit:export` | Streaming NDJSON over a PIT |
| `POST` | `/v1/audit/compliance/integrity/verify` | `audit:verify` | Chain verification report |
| `POST` | `/v1/audit/compliance/erasure` | `audit:erase` | Crypto-shred a data subject |
| `POST` | `/v1/audit/admin/tenants/{id}/dedicate` | `audit:admin` | Provision a dedicated stream |
| `GET` | `/health`, `/health/live`, `/health/ready`, `/metrics` | — | Unversioned |

### Authentication

**Service principal** — `x-api-key`, for emitting services that have already
enforced RBAC. Constant-time comparison against a list, so keys rotate with an
overlap window. Grants `write`, `read`, `verify`, `export` — deliberately **not**
`erase` or `cross_tenant`: destroying personal data and reading across tenants
are human decisions.

```
x-api-key:             <service key>
x-audit-tenant-id:     <tenant uuid>          # tenant this call acts for
x-audit-on-behalf-of:  <user uuid>            # attribution for the trail
x-service-name:        everycred-backend
```

**User principal** — `Authorization: Bearer <platform JWT>`, validated with the
same secret, issuer and audience as the main backend, so there is no separate
login.

A plain platform token carries no audit scopes, and this service has no access
to the platform's RBAC tables. Rather than guess, an unscoped token gets exactly
one grant: read access to **its own** events, with `actor_id` pinned so the
filter cannot be widened. Broader access needs a token minted with explicit
`audit_scopes`, or a service call from the main backend.

### Ingest example

```bash
curl -X POST http://localhost:8020/v1/audit/events \
  -H 'x-api-key: <key>' \
  -H 'x-audit-tenant-id: 7f3c…' \
  -H 'x-service-name: everycred-backend' \
  -H 'Content-Type: application/json' \
  -d '{
    "events": [{
      "action": "credential.issue",
      "timestamp": "2026-08-27T10:15:00+05:30",
      "outcome": "success",
      "actor":  {"type": "user", "id": "u-9a1c", "email": "issuer@example.com"},
      "target": {"type": "credential", "id": "vc-4410"},
      "source": {"ip": "203.0.113.42", "country_code": "IN"},
      "http":   {"method": "POST", "path": "/v1/credentials/issue", "status_code": 201},
      "service_name": "everycred-backend",
      "labels": {"batch_id": "b-77"}
    }]
  }'
```

`category` and `severity` are derived from the action if omitted; severity is
escalated one step on failure, because a failed privileged operation is what an
intrusion attempt looks like. Supplying a stable `event_id` makes an emitter
retry idempotent.

### Historical backfill

1. Export per-tenant rows to NDJSON (SQL sketch in `scripts/export_legacy_audit.sql`,
   or `everycred-backend/scripts/export_audit_ndjson.py`).
2. Replay into the running API:

```bash
uv run audit-service backfill --file user_audit.ndjson --dry-run   # map only
uv run audit-service backfill --file user_audit.ndjson             # POST ingest
```

Re-runs are safe: event ids are the legacy row uuids, and Elasticsearch rejects
duplicates. After a large backfill, run `audit-service verify --tenant <id>`.

### Legacy action strings

During dual-write / cutover, emitters may still hold display strings from the
old Postgres tables (`"Issue Credential (Bulk)"`, `"CREATED"`, …). Map them
with `app.domain.legacy` before posting:

```python
from app.domain.legacy import map_action, map_entity, map_status, legacy_event_hints

action, category = legacy_event_hints("Issue Credential (Bulk)")
# → Action.CREDENTIAL_ISSUE_BULK, EventCategory.CREDENTIAL
```

`map_action` also accepts an already-migrated ECS string (`"credential.issue"`)
so call sites can flip over one at a time.

---

## Query performance

Six years of retention makes naive queries expensive. The measures that matter:

| Measure | Effect |
|---|---|
| Custom routing by `tenant.id` | tenant search hits **1 shard**, not all |
| `index.sort` `@timestamp` desc | Lucene terminates early on newest-first |
| Filter context only | no scoring; results land in the node query cache |
| `track_total_hits: false` | skips counting every match across the retention window |
| `search_after` + PIT | page 500 costs the same as page 1; `from: 10000` would sort and discard 10 000 docs per shard |
| `pre_filter_shard_size: 1` | skips backing indices whose date range cannot match |
| `constant_keyword` on dedicated streams | tenant filter resolved at rewrite time |
| `flattened` for `labels` / `change` | fixed mapping cost instead of unbounded field explosion |
| `_source` field allow-list | less decompression on wide `change` diffs |
| `best_compression` + `forcemerge` in warm | ~20–30% less disk on write-once data |

Guardrails, because an unbounded audit query is a full-retention scan:
unbounded time ranges are refused (`MAX_QUERY_WINDOW_DAYS`), page size is
capped, `group_by` is a closed allow-list, and **raw Elasticsearch DSL is never
accepted** from a client — it would be a search-injection and DoS surface on a
cluster holding every tenant's data.

## Compliance mapping

| Requirement | Where |
|---|---|
| SOC 2 CC6.1 — no default secrets | `config.py` boot-time validation |
| SOC 2 CC7.2 / HIPAA 164.312(b) — audit the audit | every read/export emits `audit_log.*` |
| ISO 27001 A.12.4 — protected, immutable logs | data streams + hash chain + Object Lock |
| HIPAA 164.316(b)(2)(i) — 6 years | `RETENTION_DAYS=2190`, ILM delete phase |
| GDPR Art. 17 / DPDP s.12 — erasure | crypto-shredding |
| GDPR Art. 19 — report affected records | `ErasureReceipt.affected_events` |
| GDPR Art. 5(1)(c) — minimisation | PII never indexed; IP truncated to a prefix |
| DPDP s.8(5) — accuracy of records | insert-only; ES rejects duplicate event ids |

The ILM delete phase is the *regulatory maximum*, not the erasure mechanism.
Deleting a record early would break the chain and destroy audit evidence.

## Operations

Watch these:

- `audit_queue_total` / `queue.total` — rises before anything user-visible breaks.
- `audit_queue_dead_letter_total` / `queue.dead_letter_total` — **non-zero means
  audit events were permanently rejected** and need human attention. The DLQ is
  never trimmed.
- `audit_events_ingested_total{outcome}` — API accept vs reject counts.
- `audit_events_written_total` / `audit_events_dead_lettered_total` /
  `audit_events_duplicate_total` — worker pipeline outcomes.
- `audit_chain_resynced_from_ledger_total` — Redis chain state was cold and was
  rebuilt from Elasticsearch. Expected after a Redis failover; suspicious otherwise.
- `worm_archive_misconfigured` at startup — the bucket lacks Object Lock, so
  "immutable" segments are deletable. Object Lock can only be enabled at bucket
  creation, so this needs a new bucket.
- A failing `audit-service verify` — a real integrity incident.

**Redis must run `appendonly yes` with `appendfsync everysec`.** Without AOF it
is a buffer, not a durable queue, and the no-lost-events guarantee does not hold.
Also set `maxmemory-policy noeviction`, so memory pressure rejects writes instead
of silently evicting queued audit events.

**Apply `deploy/s3-archive-bucket-policy.json` to the archive bucket.** Object
Lock makes each object *version* immutable — a targeted version delete is refused
outright, verified against a live bucket. What it does not block is a plain
`DeleteObject`, which on a versioned bucket writes a zero-byte **delete marker**
as the current version. The sealed data survives and stays recoverable, but a
default listing then looks as though the segment is missing — which for an audit
archive is indistinguishable from lost evidence until someone thinks to list
versions. The policy denies `s3:DeleteObject` so the situation cannot arise. To
recover a segment already hidden this way, delete the *marker* version:

```bash
aws s3api list-object-versions --bucket <name> --prefix <key>
aws s3api delete-object --bucket <name> --key <key> --version-id <marker-id>
```

The keyring index is the single point of failure for PII readability: lose it and
every encrypted field is gone permanently. It must be in the snapshot policy. It
holds only *wrapped* keys, so a stolen copy is still gated by the KEK. It is
deliberately **not** archived to WORM — writing key material somewhere
undeletable would defeat crypto-shredding, which works by destroying that key.

**Run exactly one worker fleet against one Redis keyspace.** Partition leases
make a partition single-writer, and the commit re-checks lease ownership, so
extra replicas are safe. What is *not* safe is leaving an older build's worker
running against the same keyspace during a rollout: a pre-lease-check worker will
happily chain from a stale head and produce `prev_mismatch` breaks. Drain and
stop the old workers before starting new ones.

## Testing

```bash
uv run pytest                       # unit tests, no infrastructure needed
uv run pytest -m integration        # requires docker compose up
uv run ruff check . && uv run ruff format --check .
uv run mypy app
uv run bandit -c pyproject.toml -r app
uv run pip-audit
```

## Layout

```
app/
├── core/
│   ├── config.py          settings + boot-time production hardening
│   ├── integrity.py       canonical JSON, hash chain, verifier (pure)
│   ├── metrics.py         Prometheus queue/ingest counters
│   ├── security/
│   │   ├── auth.py        JWT + API key → Principal + scopes
│   │   └── crypto.py      PII encryption, crypto-shredding
│   ├── middleware/stack.py  request id, security headers, body limit, rate limit
│   ├── exceptions.py      handlers — no internals ever leak to a client
│   ├── responses.py       platform {status,data,message} envelope
│   └── logging.py         structlog JSON + secret redaction
├── domain/
│   ├── enums.py           action/category/scope taxonomy (ECS conventions)
│   ├── legacy.py          map legacy ActionType/session strings ↔ ECS Actions
│   └── events.py          canonical event + PII field registry
├── search/
│   ├── mappings.py        ILM policy, index templates, keyring mapping
│   ├── routing.py         hybrid tenant → data stream resolution
│   ├── query.py           DSL builder — the tenant isolation boundary
│   ├── repository.py      bulk write, search, PIT, aggregations
│   ├── keyring.py         wrapped-DEK store
│   ├── bootstrap.py       idempotent cluster provisioning
│   └── client.py          hardened ES client
├── queue/
│   ├── stream.py          Redis Streams producer/consumer + DLQ
│   ├── chain.py           atomic sequence allocation + ledger resync
│   └── worker.py          the ingest pipeline
├── archive/s3_worm.py     Object Lock segments + notarised checkpoints
├── services/              ingest, query, compliance
├── tools/backfill.py      legacy NDJSON → ingest replay
├── api/                   routes, deps, composition root
├── main.py                app factory
└── cli.py                 serve / worker / bootstrap / verify / generate-kek / backfill
```

See [`docs/MODULES.md`](docs/MODULES.md) for a full module-by-module catalogue.

## Documentation

| Document | Read it when |
|---|---|
| [docs/SETUP.md](docs/SETUP.md) | Getting the service running locally, first time |
| [docs/FILE_STRUCTURE.md](docs/FILE_STRUCTURE.md) | Deciding **which file** your change belongs in |
| [docs/MODULES.md](docs/MODULES.md) | Looking up what a single module does |
| [docs/TECH_STACK.md](docs/TECH_STACK.md) | Python/dependency versions, why Elasticsearch and no SQL |
| [docs/SECURITY.md](docs/SECURITY.md) | Reviewing controls, threat model, residual risks, compliance mapping |
| [docs/ELASTICSEARCH_DEPLOYMENT.md](docs/ELASTICSEARCH_DEPLOYMENT.md) | Provisioning, sizing, hardening or upgrading the cluster |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Shipping to staging/production, rollback, monitoring |