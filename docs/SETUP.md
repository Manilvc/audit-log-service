# Project setup

Local and integration setup for the EveryCRED Audit Log Service.

For module orientation see [MODULES.md](./MODULES.md). For architecture and
API contracts see the root [README.md](../README.md).

---

## Prerequisites

| Tool | Version / notes |
|---|---|
| **Python** | 3.13–3.14 (`uv` installs it via `.python-version`) |
| **uv** | [Install](https://docs.astral.sh/uv/getting-started/installation/) |
| **Docker** | Compose v2 — Elasticsearch 9, Redis 7 (AOF), MinIO |
| **Make** (optional) | Thin wrappers around the same `uv` / compose commands |

On Windows, use PowerShell for `uv` and Docker. `scripts/init-minio.sh` is bash —
use the PowerShell equivalent in
[Create the WORM bucket](#create-the-worm-bucket-object-lock) instead. Windows
also has two process-inspection traps when checking for stray workers; see
[Run exactly one worker generation](#run-exactly-one-worker-generation).

---

## 1. Clone and install

```bash
cd everycred_backend/audit

# Once per machine
curl -LsSf https://astral.sh/uv/install.sh | sh          # macOS / Linux
# powershell -c "irm https://astral.sh/uv/install.ps1 | iex"   # Windows

uv sync --all-extras
```

`uv` creates `.venv` and downloads the pinned interpreter. You do not need to
activate the venv — prefix commands with `uv run`.

---

## 2. Environment file

```bash
cp .env.example .env
uv run audit-service generate-kek
# Paste the printed value into .env as PII_MASTER_KEK=...
```

### Local overrides (recommended)

Edit `.env` for a single-node Docker stack:

| Variable | Local value | Why |
|---|---|---|
| `ENVIRONMENT` | `local` | Skips prod hardening checks |
| `INDEX_REPLICAS` | `0` | Single-node ES cannot allocate replicas |
| `ES_VERIFY_CERTS` | `false` | Local ES speaks plain `http://` |
| `ES_HOSTS` | `http://localhost:9200` | Compose publishes 9200 |
| `REDIS_URL` | `redis://localhost:6379/0` | Compose publishes 6379 |
| `S3_ENDPOINT_URL` | `http://localhost:9000` | MinIO; SSE headers are skipped automatically |
| `SERVICE_API_KEYS` | any long secret | Emitters must send the same value as `x-api-key` |
| `JWT_SECRET_KEY` | ≥32 bytes | Must match main backend `SIGNIN_SECRET_KEY` for JWT reads |
| `JWT_AUDIENCE` | `everycred-api` | Must match main backend audience |

Losing `PII_MASTER_KEK` makes every encrypted field permanently unreadable.
Do not commit `.env`.

### Aligning with everycred-backend (dual-write)

In the main backend `.env`:

```env
AUDIT_SERVICE_URL=http://localhost:8020
AUDIT_SERVICE_API_KEY=<same as SERVICE_API_KEYS above>
AUDIT_DUAL_WRITE_ENABLED=true
AUDIT_SERVICE_TIMEOUT_SECONDS=3.0
```

JWT settings on this service must match the platform signing key / audience /
issuer or Bearer tokens from the main API will fail validation here.

---

## 3. Infrastructure

Start only the data plane (API and worker run on the host via `uv`):

```bash
docker compose up -d elasticsearch redis minio
```

Wait until healthy:

```bash
docker compose ps
# audit-es, audit-redis, audit-minio → healthy
```

### Create the WORM bucket (Object Lock)

Object Lock can only be set at bucket creation. On Linux/macOS:

```bash
./scripts/init-minio.sh
```

On Windows (or without bash), from the audit directory:

```powershell
docker run --rm --network everycred-audit_default `
  -e "MC_HOST_local=http://minioadmin:minioadmin123@minio:9000" `
  minio/mc:latest mb --with-lock local/everycred-audit-archive-local

docker run --rm --network everycred-audit_default `
  -e "MC_HOST_local=http://minioadmin:minioadmin123@minio:9000" `
  minio/mc:latest retention set --default COMPLIANCE 2190d local/everycred-audit-archive-local

docker run --rm --network everycred-audit_default `
  -e "MC_HOST_local=http://minioadmin:minioadmin123@minio:9000" `
  minio/mc:latest version enable local/everycred-audit-archive-local
```

Compose project name is `everycred-audit`, so the network is
`everycred-audit_default`. Credentials match `docker-compose.yml` (dev only).

Or use Make (Linux/macOS):

```bash
make up          # compose + init-minio.sh
```

#### Object Lock is necessary but not sufficient

Verified against the live bucket: Object Lock in COMPLIANCE mode makes each
object *version* immutable — a targeted version delete is refused with
`WORM protected and cannot be overwritten`, and nobody can shorten the retention.

What it does **not** block is a plain `DeleteObject`. On a versioned bucket that
writes a zero-byte **delete marker** as the new current version. The sealed data
survives and stays recoverable, but a default listing then looks as though the
segment is gone — which for an audit archive is indistinguishable from lost
evidence until someone thinks to list versions.

For any non-local bucket, apply
[`deploy/s3-archive-bucket-policy.json`](../deploy/s3-archive-bucket-policy.json),
which denies `s3:DeleteObject` so the situation cannot arise:

```bash
aws s3api put-bucket-policy --bucket "$ARCHIVE_BUCKET" \
  --policy file://deploy/s3-archive-bucket-policy.json
```

Recovering a segment already hidden by a marker — delete the *marker* version,
which is not a data deletion:

```bash
aws s3api list-object-versions --bucket "$ARCHIVE_BUCKET" --prefix "<key>"
aws s3api delete-object --bucket "$ARCHIVE_BUCKET" --key "<key>" \
  --version-id "<marker-version-id>"
```

Startup logs `worm_archive_delete_marker_note` as a reminder; the service cannot
verify the policy itself without `s3:GetBucketPolicy`.

---

## 4. Bootstrap Elasticsearch

Idempotent. Also runs automatically on API startup.

```bash
uv run audit-service bootstrap
# or: make bootstrap
```

Creates ILM policy, shared/dedicated index templates, `audit-keyring-v1`, and
the `audit-shared` data stream.

---

## 5. Run the service

Two processes — do not combine them:

```bash
uv run audit-service serve          # HTTP :8020
uv run audit-service worker         # ingest pipeline
```

With Make:

```bash
make serve      # includes --reload
make worker
```

Optional: run API + worker as compose services (`docker compose up -d api worker`)
after `.env` is filled; container DNS overrides hostnames to `elasticsearch`,
`redis`, and `minio`.

### Run exactly one worker *generation*

Multiple worker replicas are safe — a Redis lease makes each partition
single-writer, and the commit re-verifies lease ownership inside the same Lua
script that moves the chain head. Scaling out is the normal production shape.

What is **not** safe is leaving an older build's worker running against the same
Redis keyspace. A worker from before the lease-checked commit will chain from a
stale head and produce `prev_mismatch` breaks that look exactly like tampering.
This is the single most likely way to get a broken chain during local
development, because a stray background worker survives editor restarts.

Before starting a worker, confirm none is already running:

```bash
# Linux / macOS
pgrep -af "audit-service worker|app.cli worker"
```

```powershell
# Windows — match on the command line, not the image name
Get-CimInstance Win32_Process |
  Where-Object { $_.CommandLine -match 'audit-service worker|app\.cli worker' } |
  Select-Object ProcessId, CreationDate, CommandLine
```

Two Windows gotchas, both of which cost real debugging time:

- **Every worker shows up twice.** `.venv\Scripts\python.exe` is a launcher that
  spawns the real interpreter as a child, so one worker is two PIDs. Count
  *distinct `CreationDate` pairs*, or better, count lease owners (below).
- **`uv run audit-service worker` does not match a filter on `app.cli`.** A
  worker started that way has `audit-service` in its command line instead, so a
  narrow filter silently misses it. Match both patterns.

The authoritative check is who owns the partition leases — one consumer id means
one worker generation:

```bash
docker exec audit-redis sh -c \
  'for i in $(seq 0 7); do redis-cli get "audit:stream:lease:$i"; done' | sort -u
```

Stopping a worker releases its leases immediately; a killed one expires within
30s. To reset a locally poisoned chain, stop all workers, wait for the leases to
expire, then clear the local keyspace and use a **fresh tenant id** for the next
smoke (existing documents are immutable and keep their original links):

```bash
docker exec audit-redis redis-cli --scan --pattern 'audit:chain:*' | \
  xargs -r -n1 docker exec audit-redis redis-cli del
docker exec audit-redis redis-cli --scan --pattern 'audit:stream:*' | \
  xargs -r -n1 docker exec audit-redis redis-cli del
```

---

## 6. Smoke check

Set the key once for this shell — it must match a value in `SERVICE_API_KEYS`:

```bash
export SERVICE_API_KEY='<the value you put in SERVICE_API_KEYS>'
```

```powershell
$env:SERVICE_API_KEY = '<the value you put in SERVICE_API_KEYS>'
```

```bash
# Readiness (Redis required; ES optional for ingest buffering)
curl -s http://localhost:8020/health/ready

# Ingest
curl -s -X POST http://localhost:8020/v1/audit/events \
  -H "x-api-key: $SERVICE_API_KEY" \
  -H "x-audit-tenant-id: demo-tenant" \
  -H "x-service-name: everycred-backend" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "action": "credential.issue",
      "event_id": "demo-001",
      "outcome": "success",
      "actor":  {"type": "user", "id": "u-1"},
      "target": {"type": "credential", "id": "vc-1"},
      "service_name": "everycred-backend"
    }]
  }'

# Wait ~1–2s for the worker, then fetch
curl -s http://localhost:8020/v1/audit/events/demo-001 \
  -H "x-api-key: $SERVICE_API_KEY" \
  -H "x-audit-tenant-id: demo-tenant"

# Integrity gate (exits non-zero on a break)
uv run audit-service verify --tenant demo-tenant
```

Search example (typed filters; no raw ES DSL):

```bash
curl -s -X POST http://localhost:8020/v1/audit/events/search \
  -H "x-api-key: $SERVICE_API_KEY" \
  -H "x-audit-tenant-id: demo-tenant" \
  -H "Content-Type: application/json" \
  -d '{"event_ids":["demo-001"],"size":10,"with_total":true}'
```

OpenAPI (when `ENABLE_DOCS=true`): http://localhost:8020/docs

---

## 7. Tests and quality gates

```bash
uv run pytest -m "not integration"   # 261 unit tests — no Docker needed
uv run pytest -m integration         # 24 integration tests — needs ES + Redis
uv run pytest                        # all 285
make check                           # lint + format + mypy + unit + bandit + pip-audit
```

The integration suite needs only `docker compose up -d elasticsearch redis` —
**not** MinIO, and **not** a prior `bootstrap`. Each module provisions its own
run-scoped ILM policy, templates, data stream and Redis key prefix, then tears
them down, so runs never collide with each other or with your local stack.

Two files, covering different things:

| File | Verifies |
|---|---|
| `tests/integration/test_end_to_end.py` | Guarantees enforced *by Elasticsearch*: `constant_keyword` rejecting a wrong-tenant document, `enabled: false` making ciphertext unsearchable, `op_type: create` rejecting a replay, `dynamic: strict` rejecting an undeclared field, PIT snapshot consistency, cursor pagination |
| `tests/integration/test_worker_pipeline.py` | Runs the **real worker in-process**: chain integrity across batch boundaries, contiguous sequences, redelivery absorption, worker restart, PII encryption, dead-lettering |

These are not optional coverage. Every check in them has already caught a real
defect — including a mapping that broke all pagination, and a routing setting
that would have rejected 100% of writes for dedicated tenants. CI runs them in a
separate job with ES and Redis service containers
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).

---

## 8. Historical backfill (optional)

1. Export rows from a tenant DB (see `scripts/export_legacy_audit.sql` or
   `everycred-backend/scripts/export_audit_ndjson.py`).
2. Replay:

```bash
uv run audit-service backfill --file user_audit.ndjson --dry-run
uv run audit-service backfill --file user_audit.ndjson
uv run audit-service verify --tenant <tenant-id>
```

Re-runs are idempotent on legacy row uuids (`event_id`).

---

## Ports

| Port | Service |
|---|---|
| 8020 | Audit API |
| 9200 | Elasticsearch |
| 6379 | Redis |
| 9000 | MinIO S3 API |
| 9001 | MinIO console |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Settings validation error on boot | Missing `PII_MASTER_KEK` / short JWT secret | Generate KEK; JWT HS256 needs ≥32 bytes (enforced at startup, RFC 7518 §3.2) |
| ES yellow / replica unassigned | `INDEX_REPLICAS=1` on one node | Set `INDEX_REPLICAS=0` locally |
| ES container exits: `unknown setting [xpack.ilm.enabled]` | That setting was **removed in ES 9.x** — ILM is always on | Drop it from compose / k8s env. Already fixed in `docker-compose.yml` |
| **Integrity `prev_mismatch` on a fresh tenant** | **A stale worker generation is still running against the same Redis keyspace** — by far the most common cause | Stop *all* workers (see [Run exactly one worker generation](#run-exactly-one-worker-generation)), confirm one lease owner, clear `audit:chain:*`, retest on a new tenant id |
| Integrity `gap` with no `prev_mismatch` | Sequences reserved but never written (worker died mid-batch) | Benign and expected; the worker logs `batch_was_redelivery_chain_resynced` explaining the orphaned range |
| `bootstrap` fails: *a concrete index named 'audit-shared' exists* | Events reached the cluster **before** the index template did, so ES auto-created a plain index. It permanently blocks the data stream of the same name | Reindex anything you need, then `DELETE /audit-shared` and re-run bootstrap. The guard converts ES's opaque 500 into this message |
| Ingest 202 but GET 404 | Worker not running, or its lease is held by a stale worker | Start `audit-service worker`; check lease owners |
| Worker logs look truncated / batches missing | Windows: the launcher shim and the real interpreter share one redirected stdout | Don't diagnose from a `nohup` log. Query ES, or run the worker in the foreground |
| `archive_seal_failed` / KMS NotImplemented | SSE sent to MinIO | SSE is skipped automatically when `S3_ENDPOINT_URL` is set (`s3_worm.py`) |
| Sealed segment vanished from `mc ls` / `s3 ls` | A plain `DeleteObject` wrote a delete marker; the locked version survives | Apply the bucket policy; recover by deleting the *marker* version |
| Bucket exists without Object Lock | Created without `--with-lock` | New bucket name + re-run init — Object Lock **cannot** be added later |
| JWT 401 from UI/main backend | Secret / audience / issuer mismatch | Copy values from main backend signing config |
| JWT accepted but only own events visible | Token carries no `audit_scopes`, so it gets self-service read only | Mint the token with explicit scopes, or call via the backend's service key |
| Dual-write silent no-ops | Flag or key missing | `AUDIT_DUAL_WRITE_ENABLED=true` and matching API key |

Redis **must** run with `appendonly yes` *and* `maxmemory-policy noeviction`
(compose sets both). Without AOF it is a buffer rather than a durable queue, and
without `noeviction` memory pressure silently discards queued audit events
instead of rejecting the write — either way the no-lost-events guarantee fails.

---

## Useful Make targets

| Target | Action |
|---|---|
| `make install` | `uv sync --all-extras` |
| `make up` / `make down` | Start / stop ES + Redis + MinIO |
| `make bootstrap` | Apply ES topology |
| `make serve` / `make worker` | Run API (reload) / worker |
| `make test` / `make test-all` | Unit / all tests |
| `make check` | Full CI gate |
| `make verify TENANT=…` | Integrity check |

---

## Next steps after local setup

1. Point everycred-backend dual-write env vars at this service.
2. Exercise a login or credential-issue flow and confirm events via search.
3. Review [MODULES.md](./MODULES.md) before changing ingest or query paths.
4. For production: TLS ES hosts, `OBJECT_LOCK_MODE=COMPLIANCE` on real S3,
   nginx deny of `/metrics` (`deploy/nginx/audit.conf`), and shared
   `SERVICE_API_KEYS` rotation with emitters.
