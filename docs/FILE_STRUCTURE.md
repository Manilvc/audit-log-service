# File structure and responsibilities

What belongs in each file, and where a given change should go.

[MODULES.md](./MODULES.md) is the one-line index of every module. This document
is the deeper companion: it explains the *boundaries* — what each layer is
allowed to know about, and which file you should open for a given task.

- Setup: [SETUP.md](./SETUP.md)
- Architecture and API contracts: [../README.md](../README.md)
- Tech stack and versions: [TECH_STACK.md](./TECH_STACK.md)
- Security controls: [SECURITY.md](./SECURITY.md)

---

## Tree

```
audit/
├── pyproject.toml              dependencies, tool config (ruff/mypy/bandit/pytest)
├── uv.lock                     exact resolved versions — committed, CI uses --frozen
├── .python-version             3.14 (uv downloads it)
├── .env.example                every setting, documented; template for .env
├── Dockerfile                  multi-stage build, non-root runtime
├── docker-compose.yml          local data plane (ES + Redis + MinIO) and optional app
├── Makefile                    thin wrappers over uv/compose
│
├── app/
│   ├── main.py                 FastAPI factory, lifespan, middleware order
│   ├── cli.py                  serve / worker / bootstrap / generate-kek / verify / backfill
│   │
│   ├── api/                    ── HTTP layer ──
│   │   ├── container.py        composition root: builds every collaborator once
│   │   ├── deps.py             FastAPI Depends wiring, principal resolution
│   │   ├── router.py           router assembly (the full route inventory)
│   │   └── v1/
│   │       ├── events.py       ingest, search, get, aggregate, export
│   │       ├── compliance.py   integrity verify, subject erasure
│   │       └── ops.py          health probes, /metrics, tenant admin
│   │
│   ├── schemas/api.py          ── wire contracts ── request/response models
│   │
│   ├── services/               ── use-cases ──
│   │   ├── ingest_service.py   validate → resolve tenant → enqueue
│   │   ├── query_service.py    scope → search → decrypt → audit-the-audit
│   │   └── compliance_service.py  chain verification, crypto-shred erasure
│   │
│   ├── domain/                 ── the model, no I/O ──
│   │   ├── enums.py            ECS taxonomy: actions, categories, scopes, severity
│   │   ├── events.py           canonical event + PII field registry
│   │   └── legacy.py           legacy display strings ↔ ECS actions
│   │
│   ├── search/                 ── Elasticsearch ──
│   │   ├── client.py           hardened AsyncElasticsearch factory
│   │   ├── mappings.py         ILM policy, index templates, field mappings
│   │   ├── bootstrap.py        idempotent provisioning
│   │   ├── routing.py          tenant → data stream (shared vs dedicated)
│   │   ├── query.py            DSL builder — the tenant isolation boundary
│   │   ├── repository.py       bulk write, search, PIT, aggregations
│   │   └── keyring.py          wrapped-DEK store
│   │
│   ├── queue/                  ── durable ingest ──
│   │   ├── stream.py           Redis Streams, consumer groups, DLQ
│   │   ├── chain.py            atomic seq reservation + head commit (Lua)
│   │   └── worker.py           encrypt → chain → ES → WORM → commit → ack
│   │
│   ├── archive/s3_worm.py      ── Object Lock segments + checkpoints ──
│   │
│   ├── core/                   ── cross-cutting infrastructure ──
│   │   ├── config.py           typed settings + boot-time prod hardening
│   │   ├── integrity.py        canonical JSON + hash chain (pure functions)
│   │   ├── security/
│   │   │   ├── auth.py         JWT / API key → Principal + scopes
│   │   │   └── crypto.py       per-subject AES-GCM, crypto-shredding
│   │   ├── middleware/stack.py request id, security headers, body limit, rate limit
│   │   ├── exceptions.py       error types + global handlers
│   │   ├── responses.py        {status, data, message} envelope
│   │   ├── logging.py          structlog JSON + secret redaction
│   │   └── metrics.py          Prometheus counters and gauges
│   │
│   └── tools/backfill.py       legacy NDJSON → ingest API
│
├── tests/
│   ├── conftest.py             shared fixtures, env bootstrap, in-memory keyring
│   ├── unit/                   261 tests, no infrastructure
│   └── integration/            24 tests, live ES + Redis
│
├── docs/                       this directory
├── deploy/
│   ├── nginx/audit.conf        reverse proxy: TLS, /metrics deny, rate limits
│   └── s3-archive-bucket-policy.json   denies DeleteObject on the WORM bucket
├── elasticsearch/audit-service-role.json   least-privilege cluster role
└── scripts/
    ├── init-minio.sh           create the local Object Lock bucket
    └── export_legacy_audit.sql export legacy rows for backfill
```

---

## Layering rule

Dependencies point **inward only**:

```
api  →  services  →  search / queue / archive  →  core  →  domain
```

`domain` imports nothing from the service. `core.integrity` is pure functions —
no I/O, no globals — so a verifier can re-derive a hash from an archived
document years from now without booting anything.

If you find yourself importing `app.api` from `app.services`, or Elasticsearch
from `app.domain`, the change is in the wrong file.

---

## Where does my change go?

| Task | File(s) | Notes |
|---|---|---|
| **Add a new audit action** (e.g. `credential.suspend`) | `domain/enums.py` | Add to `Action`; add a `DEFAULT_SEVERITY` entry if it is security-relevant. Values are permanent — a rename orphans six years of history |
| **Add a field to the event** | `domain/events.py` → `search/mappings.py` → `schemas/api.py` | All three, in that order. The mapping is `dynamic: strict`, so an unmapped field is rejected at ingest |
| **Mark a field as PII** | `domain/events.py` → `PII_FIELD_PATHS` | One registry drives encryption, shredding and read-side redaction. Also remove it from `mappings.py` so it can never be indexed |
| **Add a search filter** | `schemas/api.py` → `search/query.py` → `services/query_service.py` | Typed filter first, then the DSL clause, then the translation. Never accept raw DSL |
| **Add an endpoint** | `api/v1/*.py` → `api/router.py` | Must be registered in `router.py`; that file is the security-review surface |
| **Add a config setting** | `core/config.py` → `.env.example` | Add a prod-hardening check in `_enforce_production_hardening` if an unsafe value is possible |
| **Change the ingest pipeline** | `queue/worker.py` | Read the module docstring first: the write ordering and the lease rules are load-bearing, not stylistic |
| **Change index topology** | `search/mappings.py` → `search/bootstrap.py` | Template names derive from `INDEX_PREFIX`. Re-applying a template whose pattern no longer matches a live data stream is rejected by ES |
| **Change tenant routing** | `search/routing.py` | `TenantRouter` is pure and cheap. Partition assignment must stay stable — the hash chain depends on it |
| **Add a scope / change authz** | `domain/enums.py` (`Scope`) → `core/security/auth.py` | Then enforce with `principal.require(...)` at the service layer, not the route |
| **Add a metric** | `core/metrics.py` | Increment on the hot path; poll gauges in `api/v1/ops.py` |
| **Add an operational command** | `cli.py` | Import inside the command body so `--help` stays fast and does not build a container |
| **Add secret-shaped keys to redact** | `domain/events.py` → `REDACT_KEYS` | Applies to `labels` and `change` diffs at the API boundary, and to all log output |

---

## The three files to read before changing anything

1. **`app/search/query.py`** — the tenant isolation boundary. The cluster runs
   the Basic licence, so there is no document-level security. If a query leaves
   this file without a tenant constraint, one customer reads another's audit
   trail. `tests/unit/test_tenant_isolation.py` asserts the invariant over every
   filter permutation.

2. **`app/queue/worker.py`** — the write ordering (`reserve → hash → ES →
   archive → commit → ack`), the three-level partition lease, and the
   redelivery branch. Each rule exists because violating it produced a broken
   chain, and a broken chain is indistinguishable from tampering.

3. **`app/core/security/crypto.py`** — why DEKs are random rather than derived
   (a derived key is recomputable, so "deletion" would be theatre), and why the
   hash is computed over ciphertext (so erasure years later does not invalidate
   the chain).

---

## File-by-file responsibilities

### `app/main.py` and `app/cli.py`

`main.py` owns the app factory and, critically, **middleware order**. Starlette
applies `add_middleware` in reverse, so registration order is the inverse of
execution order — the comment in `_install_middleware` explains the intended
chain. Startup failures (bootstrap, queue groups, WORM verification) are logged
but do **not** abort boot: a replica that cannot reach Elasticsearch must still
come up and buffer writes.

`cli.py` is the supported entrypoint. Heavy imports live inside command bodies.

### `app/api/`

| File | Owns | Does not own |
|---|---|---|
| `container.py` | Constructing every collaborator, once | Business logic |
| `deps.py` | Credential → `Principal`; container access | Authorisation decisions |
| `router.py` | The complete route inventory | Handlers |
| `v1/*.py` | HTTP shape: status codes, headers, streaming | Scope checks, tenant resolution, ES access |

Routes stay thin. They call a service and wrap the result in `success(...)`.
Authorisation and tenant scoping belong in the service layer, so the CLI and the
worker get the same checks without going through HTTP.

### `app/schemas/api.py`

Wire models, separate from the domain model on purpose: emitters send a forgiving
shape (timestamp defaults to now, category inferred, severity derived) while the
domain model stays strict and fully normalised. Every model sets
`extra="forbid"` — a typo in an emitter's payload must be a 422 now, not a
missing audit field discovered during an incident.

### `app/services/`

Where authorisation, tenant scoping and orchestration live. Each service takes
its collaborators by constructor injection, so tests substitute fakes without
patching module globals.

### `app/domain/`

The model. No I/O, no framework imports. `enums.py` values are an external
contract: they are stored as `keyword` in Elasticsearch and must never be
renamed. `events.py` holds `PII_FIELD_PATHS` and `REDACT_KEYS`, the two
registries that three separate subsystems read.

### `app/search/`

`mappings.py` explains *why* each mapping choice was made — `dynamic: strict`,
`flattened` for free-form subtrees, `constant_keyword` for dedicated-stream
tenant ids, `index.sort` for early termination. Read those comments before
changing a field type; several are load-bearing for either isolation or cost.

`query.py` builds DSL from a typed filter and takes a `TenantScope`. There is no
code path that omits the tenant constraint.

`repository.py` is the only module that talks to the cluster about audit
documents. Callers pass a scope, never an index name.

### `app/queue/`

`stream.py` wraps Redis Streams. `chain.py` holds the Lua scripts for atomic
sequence reservation and lease-verified head commit — the atomicity is the
guarantee, so changes here need the tests in
`tests/unit/test_chain_allocator.py`.

`worker.py` is the pipeline. Its early returns are deliberate: each one leaves
the batch unacknowledged so the queue redelivers rather than losing evidence.

### `app/core/`

Cross-cutting only. Nothing here knows about audit events specifically, except
`integrity.py` (hash-chain rules) and the two PII registries it reads from
`domain`. `config.py` fails the boot on an unsafe production configuration
rather than starting and hoping.

---

## Tests mirror the source tree

| Test file | Covers |
|---|---|
| `unit/test_tenant_isolation.py` | `search/query.py`, `search/routing.py` — 86 tests |
| `unit/test_integrity.py` | `core/integrity.py` — one test per attack class |
| `unit/test_crypto_shredding.py` | `core/security/crypto.py` |
| `unit/test_auth.py` | `core/security/auth.py` |
| `unit/test_chain_allocator.py` | `queue/chain.py` incl. concurrency and leases |
| `unit/test_ingest_and_schemas.py` | `services/ingest_service.py`, `schemas/api.py` |
| `unit/test_legacy.py`, `unit/test_backfill.py` | `domain/legacy.py`, `tools/backfill.py` |
| `integration/test_end_to_end.py` | Guarantees enforced *by Elasticsearch* |
| `integration/test_worker_pipeline.py` | The real worker: chain integrity, redelivery, restart |

A change to an isolation, integrity or crypto file without a corresponding test
change should not pass review.

---

## Non-Python files

| File | Needed for |
|---|---|
| `pyproject.toml` | Dependencies plus ruff/mypy/bandit/pytest config in one place |
| `uv.lock` | Reproducible builds. Committed; CI installs with `--frozen` |
| `.env.example` | The documented inventory of every setting — keep in sync with `config.py` |
| `Dockerfile` | Builder/runtime split so no compiler or uv reaches the final image |
| `docker-compose.yml` | Local ES + Redis (AOF, noeviction) + MinIO (Object Lock) |
| `deploy/nginx/audit.conf` | TLS termination, `/metrics` deny, per-endpoint rate limits |
| `deploy/s3-archive-bucket-policy.json` | Denies `s3:DeleteObject` — Object Lock alone does not stop delete markers |
| `elasticsearch/audit-service-role.json` | Least-privilege role: no `delete` on audit streams |
| `.github/workflows/ci.yml` | Unit gate plus an integration job with ES/Redis containers |
