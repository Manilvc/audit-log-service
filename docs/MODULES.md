# Module catalogue

One-line orientation for every Python package and module in the audit service.
Authoritative detail lives in each file's module docstring.

**Setup:** [SETUP.md](./SETUP.md)

## Application root

| Module | Description |
|---|---|
| `app` | Package root; version + layout map of the whole service |
| `app.main` | FastAPI application factory, startup bootstrap, shutdown |
| `app.cli` | Click CLI: `serve`, `worker`, `bootstrap`, `generate-kek`, `verify`, `backfill` |

## `app.api` — HTTP layer

| Module | Description |
|---|---|
| `app.api` | Routers, dependencies, composition root |
| `app.api.container` | Builds ES/Redis/cipher/services once at startup |
| `app.api.deps` | FastAPI `Depends` wiring and principal resolution |
| `app.api.router` | Assembles versioned + ops routers in one place |
| `app.api.v1` | Versioned routes under `/v1` |
| `app.api.v1.events` | Ingest, search, get, aggregate, export |
| `app.api.v1.compliance` | Integrity verify + crypto-shred erasure |
| `app.api.v1.ops` | Health, metrics, dedicate-tenant admin |

## `app.archive`

| Module | Description |
|---|---|
| `app.archive` | S3 Object Lock WORM package |
| `app.archive.s3_worm` | Seal event segments + notarised chain checkpoints |

## `app.core` — infrastructure

| Module | Description |
|---|---|
| `app.core` | Config, logging, metrics, middleware, responses, exceptions |
| `app.core.config` | Typed env settings + production hardening at boot |
| `app.core.exceptions` | Domain errors + global handlers (no internals leak) |
| `app.core.integrity` | Canonical JSON + SHA-256 hash-chain primitives (pure) |
| `app.core.logging` | structlog JSON logging with secret redaction |
| `app.core.metrics` | Prometheus counters/gauges for the ingest pipeline |
| `app.core.responses` | Platform `{status,data,message}` envelope + orjson |
| `app.core.middleware` | ASGI middleware package |
| `app.core.middleware.stack` | Request id, security headers, body limit, rate limit |
| `app.core.security` | Auth + PII crypto package |
| `app.core.security.auth` | JWT / API-key → `Principal` + scopes |
| `app.core.security.crypto` | Per-subject AES-GCM + crypto-shredding |

## `app.domain`

| Module | Description |
|---|---|
| `app.domain` | Taxonomy + canonical event model |
| `app.domain.enums` | ECS actions, categories, outcomes, scopes, severity defaults |
| `app.domain.events` | Strict internal event + PII field registry |
| `app.domain.legacy` | Legacy Postgres display strings ↔ ECS actions |

## `app.queue`

| Module | Description |
|---|---|
| `app.queue` | Redis Streams buffer + worker pipeline |
| `app.queue.stream` | Partitioned streams, consumer groups, DLQ |
| `app.queue.chain` | Atomic seq reservation + head commit (Lua) |
| `app.queue.worker` | Encrypt → chain → ES bulk → WORM seal → ack |

## `app.schemas`

| Module | Description |
|---|---|
| `app.schemas` | Wire models package |
| `app.schemas.api` | Request/response Pydantic contracts (`extra=forbid`) |

## `app.search`

| Module | Description |
|---|---|
| `app.search` | Elasticsearch integration package |
| `app.search.client` | Hardened AsyncElasticsearch client factory |
| `app.search.bootstrap` | Idempotent ILM / templates / streams / keyring |
| `app.search.mappings` | Index templates, ILM policy, field mappings |
| `app.search.routing` | Hybrid shared vs dedicated stream resolution |
| `app.search.query` | Tenant-scoped DSL builder (isolation boundary) |
| `app.search.repository` | Bulk write, search, PIT export, aggregations |
| `app.search.keyring` | Wrapped DEK store for crypto-shredding |

## `app.services`

| Module | Description |
|---|---|
| `app.services` | Application use-cases |
| `app.services.ingest_service` | Validate, resolve tenant, enqueue |
| `app.services.query_service` | Scoped reads + decrypt + audit-of-audit |
| `app.services.compliance_service` | Chain verify + subject erasure |

## `app.tools`

| Module | Description |
|---|---|
| `app.tools` | Operational one-offs |
| `app.tools.backfill` | Legacy NDJSON → ingest API mapper/runner |

## Tests

| Module | Description |
|---|---|
| `tests` | Suite root |
| `tests.conftest` | Shared fixtures + env bootstrap |
| `tests.unit` | Fast tests without infrastructure |
| `tests.integration` | E2E against compose (ES/Redis/MinIO) |
