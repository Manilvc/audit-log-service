# Technology stack

Every version below was read from the installed environment and `uv.lock`, not
from memory. Reproduce with `uv run python -m pip list --format=freeze`.

- File layout: [FILE_STRUCTURE.md](./FILE_STRUCTURE.md)
- Security controls: [SECURITY.md](./SECURITY.md)
- Elasticsearch deployment: [ELASTICSEARCH_DEPLOYMENT.md](./ELASTICSEARCH_DEPLOYMENT.md)
- Service deployment: [DEPLOYMENT.md](./DEPLOYMENT.md)

---

## At a glance

| Layer | Choice |
|---|---|
| Language | Python **3.14** (floor 3.13) |
| Package manager | **uv** (not Poetry) |
| Web framework | FastAPI + Uvicorn |
| Primary datastore | **Elasticsearch 9.x** data streams |
| Ingest buffer | **Redis 7.4** Streams (AOF) |
| Immutable archive | **S3 Object Lock** (COMPLIANCE), MinIO locally |
| Key store | Elasticsearch index (`audit-keyring-v1`) |
| Relational DB | **None** — see [Why no SQL database](#why-no-sql-database) |

There is no ORM, no Alembic and no MySQL in this service. That is a deliberate
departure from the rest of the platform and is explained below.

---

## Python

| Item | Value |
|---|---|
| Development / container | **3.14** (`.python-version`; uv downloads it) |
| Declared range | `requires-python = ">=3.13,<3.15"` |
| Build backend | `hatchling` |
| Package name / version | `everycred-audit-service` 1.0.0 |

The floor is 3.13 so the service can also run on the interpreter the rest of the
platform currently uses; the container and CI both pin 3.14.

### Why uv rather than Poetry

The sibling `everycred-consent-management-backend` uses Poetry. This service uses
uv because:

- It resolves and installs an order of magnitude faster, which matters most in CI.
- It manages the **interpreter** too, so `.python-version` is enough — no pyenv.
- `uv.lock` is committed and CI installs with `--frozen`, so a build fails rather
  than silently resolving versions that were never tested.
- `pyproject.toml` is standard PEP 621, so nothing is Poetry-specific.

Dependencies are declared as **lower bounds** (`fastapi>=0.115`) with exact
versions pinned in `uv.lock`. The one exception is Elasticsearch, pinned to a
major: `elasticsearch>=9,<10`, because the client refuses to talk to a cluster of
a different major version.

---

## Runtime dependencies

| Package | Declared | Installed | Role |
|---|---|---|---|
| `fastapi` | `>=0.115` | 0.141.1 | HTTP framework |
| `uvicorn[standard]` | `>=0.32` | 0.52.4 | ASGI server |
| `pydantic[email]` | `>=2.9` | 2.13.4 | Validation, wire + domain models |
| `pydantic-settings` | `>=2.5` | 2.15.0 | Typed env configuration |
| `elasticsearch[async]` | `>=9,<10` | 9.5.0 | Async ES client |
| `redis[hiredis]` | `>=5` | 8.1.0 | Streams client (`>=5` for `XAUTOCLAIM`) |
| `aioboto3` | `>=13` | 15.5.0 | Async S3 for the WORM archive |
| `pyjwt` | `>=2.9` | 2.13.0 | Platform token verification |
| `cryptography` | `>=43` | 50.0.1 | AES-256-GCM, HKDF |
| `structlog` | `>=24.4` | 26.1.0 | Structured logging + redaction |
| `prometheus-client` | `>=0.21` | 0.26.0 | Metrics |
| `click` | `>=8.1` | 8.5.0 | CLI |
| `orjson` | `>=3.10` | 3.12.0 | Fast, deterministic JSON |
| `httpx` | `>=0.27` | 0.28.1 | Outbound HTTP (backfill, tests) |
| `python-dotenv` | `>=1.0` | 1.2.3 | `.env` loading |
| `python-multipart` | `>=0.0.12` | 0.0.32 | Form parsing |
| `hiredis` | (extra) | 3.4.1 | C parser for Redis |

`orjson` is not only a speed choice: `OPT_SORT_KEYS` gives **deterministic**
serialisation, which the hash chain depends on. The same logical document must
produce identical bytes on every machine and Python version, forever.

## Development dependencies

| Package | Installed | Role |
|---|---|---|
| `pytest` | 9.1.1 | Test runner |
| `pytest-asyncio` | 1.4.0 | Async tests (session-scoped loop) |
| `pytest-cov` | 7.1.0 | Coverage |
| `fakeredis[lua]` | 2.37.1 | In-memory Redis **with Lua** |
| `lupa` | 2.8 | Lua runtime for fakeredis |
| `ruff` | 0.16.4 | Lint + format (replaces black/isort/flake8) |
| `mypy` | 2.3.1 | Type checking, `strict` |
| `bandit` | 1.9.4 | SAST |
| `pip-audit` | — | Dependency CVE scan |

The `[lua]` extra is required, not cosmetic: the chain allocator's atomicity
lives in Lua scripts, and testing it without a Lua runtime would leave the
sequencing guarantee unverified.

---

## Infrastructure

| Component | Version | Notes |
|---|---|---|
| Elasticsearch | **9.2.0** | Basic licence — no document-level security |
| Redis | **7.4-alpine** | `appendonly yes`, `appendfsync everysec`, `maxmemory-policy noeviction` |
| MinIO | `RELEASE.2025-04-22T22-12-26Z` | Local stand-in for S3 Object Lock |
| Container base | `python:3.14-slim-bookworm` | Builder + runtime stages |
| uv in image | `ghcr.io/astral-sh/uv:0.9.7` | Pinned artefact, not pip-installed |
| Reverse proxy | nginx | `deploy/nginx/audit.conf` |

### Ports

| Port | Service |
|---|---|
| 8020 | Audit API |
| 9200 | Elasticsearch |
| 6379 | Redis |
| 9000 / 9001 | MinIO S3 API / console |

---

## Data stores, and what each is for

### Elasticsearch 9.x — the system of record for search

Data streams with ILM. Hybrid tenant isolation: a shared stream by default, a
dedicated stream per high-volume tenant. Full detail in
[ELASTICSEARCH_DEPLOYMENT.md](./ELASTICSEARCH_DEPLOYMENT.md).

Two indices matter:

| Index | Kind | Mutable? | Purpose |
|---|---|---|---|
| `audit-shared`, `audit-t-<tenant>` | Data stream | **Append-only** | Audit events |
| `audit-keyring-v1` | Normal index | **Mutable** | Wrapped per-subject DEKs |

The keyring is the one mutable store in the service, and deliberately so:
deleting from it *is* the crypto-shredding mechanism.

### Redis 7.4 Streams — the durable ingest buffer

Writing straight to Elasticsearch makes every cluster hiccup — a rolling
restart, a mapping error, a full disk — into lost audit evidence. Redis Streams
give an append-only log with consumer groups and explicit acknowledgement, so an
event is removed only once it is durably in Elasticsearch.

Redis also holds two pieces of coordination state:

- `audit:chain:<tenant>:<partition>` — the hot pointer to each chain head.
  Elasticsearch remains authoritative; this is a cache and is reconciled against
  the ledger, never trusted blindly.
- `audit:stream:lease:<partition>` — the partition lease that makes a partition
  single-writer.

**AOF is not optional.** Without `appendonly yes` Redis is a buffer rather than a
queue, and the no-lost-events guarantee does not hold. `noeviction` matters
equally: under memory pressure Redis must reject writes rather than silently
evict queued audit events.

### S3 Object Lock — the immutable archive

Segments of events plus periodic chain checkpoints, written in COMPLIANCE mode.
The hash chain proves no single record was altered; the checkpoint is what makes
a wholesale rewrite of the chain detectable, because it cannot be changed even by
the account root.

### Why no SQL database

The rest of the platform runs MySQL with async SQLAlchemy and Alembic. This
service has none, because the workload is the opposite shape:

| Property | This service | A relational store |
|---|---|---|
| Write pattern | Append-only, never updated | Row updates expected |
| Read pattern | Ad-hoc filtering over 6 years | Indexed lookups on known keys |
| Volume | Every action on the platform | Bounded by entity count |
| Retention | 2,190 days with tiering | Manual archival |
| Aggregation | Terms + date histograms for dashboards | `GROUP BY` at increasing cost |

The queries that justify this service — *"everything this user did last March"* —
are full-text and time-series shaped. In MySQL they need the four-table joins
that motivated replacing the legacy tables in the first place. Elasticsearch also
provides ILM tiering and rollover, which would otherwise be a cron job nobody
maintains.

Consequences worth stating plainly: no transactions, no foreign keys, and
near-real-time reads (a 1-second refresh interval). All three are acceptable
because each event is independent, immutable, and never read back in the
request that wrote it.

---

## Architectural choices and their cost

| Choice | Benefit | Accepted cost |
|---|---|---|
| Queue in front of ES | No lost events during an ES outage | Events are searchable ~1s after `202`, not immediately |
| Hash chain per (tenant, partition) | Modification, deletion and reordering are all detectable | A partition must be single-writer, enforced by a Redis lease |
| Crypto-shredding for erasure | GDPR/DPDP erasure on an immutable log | Losing `PII_MASTER_KEK` makes all PII permanently unreadable |
| PII never indexed | No oracle over personal data | Cannot search by email; search is by stable ids |
| `dynamic: strict` mapping | An undeclared field fails loudly | Adding a field needs a template update before deploy |
| Shared stream + routing | Tenant search hits one shard | A very large tenant needs promoting to a dedicated stream |
| ES Basic licence | No licence cost | No document-level security; isolation is a code invariant |

---

## API surface

Base path `/v1`. Responses use the platform envelope
`{"status", "data", "message"}`, matching `core/utils/standard_response.py` in the
main backend, so existing clients parse audit responses unchanged.

| Method | Path | Scope |
|---|---|---|
| `POST` | `/v1/audit/events` | `audit:write` |
| `POST` | `/v1/audit/events/search` | `audit:read` |
| `GET` | `/v1/audit/events/{event_id}` | `audit:read` |
| `POST` | `/v1/audit/events/aggregate` | `audit:read` |
| `POST` | `/v1/audit/events/export` | `audit:export` |
| `POST` | `/v1/audit/compliance/integrity/verify` | `audit:verify` |
| `POST` | `/v1/audit/compliance/erasure` | `audit:erase` |
| `POST` | `/v1/audit/admin/tenants/{id}/dedicate` | `audit:admin` |
| `GET` | `/health`, `/health/live`, `/health/ready`, `/metrics` | — |

Health and metrics sit outside the version prefix so probe configuration does not
change when the API version does.

---

## Processes

| Process | Command | Scales on |
|---|---|---|
| API | `audit-service serve` | Request rate |
| Worker | `audit-service worker` | Ingest throughput |

Separate processes on purpose: a slow WORM archive write never adds latency to an
emitting service's request. Multiple worker replicas are safe — the partition
lease makes each partition single-writer and the commit re-verifies lease
ownership.

## Configuration

63 typed settings in `app/core/config.py`, all from the environment, documented
in `.env.example`. Secrets have **no defaults** — the service refuses to start
rather than fall back to a guessable value.

Eight production checks run at boot and fail the process: `DEBUG` off,
`ENABLE_DOCS` off, `ES_VERIFY_CERTS` on, `ES_HOSTS` https, CORS not `*`,
`ARCHIVE_BUCKET` set, `OBJECT_LOCK_MODE=COMPLIANCE`, `SERVICE_API_KEYS` set.
Plus an HMAC key-length check (RFC 7518 §3.2): HS256 requires ≥32 bytes.

## Quality gates

| Gate | Command | Status |
|---|---|---|
| Lint + format | `uv run ruff check . && uv run ruff format --check .` | clean |
| Types | `uv run mypy app` (strict) | clean, 49 files |
| SAST | `uv run bandit -c pyproject.toml -r app` | no findings |
| Dependency CVEs | `uv run pip-audit` | none known |
| Unit tests | `uv run pytest -m "not integration"` | 261 passing |
| Integration | `uv run pytest -m integration` | 24 passing |

`mypy` runs in `strict` mode deliberately: a mistyped tenant filter is a
data-leak bug, not a style problem.

---

## Platform integration

| Contract | Value |
|---|---|
| JWT algorithm | HS256, key shared with `SIGNIN_SECRET_KEY` |
| JWT claims read | `sub` (JSON `{email, uuid}`), `tenant_id`, `sid`, `aud`, `iss` |
| Service auth | `x-api-key`, constant-time compare against a rotatable list |
| Tenant header | `x-audit-tenant-id` |
| Attribution header | `x-audit-on-behalf-of` |
| Response envelope | `{status, data, message}` |

The main backend's `sub` claim holds `json.dumps({"email": ..., "uuid": ...})`;
older tokens carry a bare string. Both are accepted, so deploying this service
does not force a fleet-wide re-login.
