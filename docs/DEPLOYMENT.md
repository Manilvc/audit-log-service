# Deployment

Deploying the audit log service to a shared environment: build, configure,
release, roll back and operate.

For local development use [SETUP.md](./SETUP.md). For the cluster itself see
[ELASTICSEARCH_DEPLOYMENT.md](./ELASTICSEARCH_DEPLOYMENT.md).

---

## What gets deployed

Two processes from **one image**, differing only in the command:

| Process | Command | Scales on | Replicas |
|---|---|---|---|
| API | `audit-service serve` | Request rate | ≥2 behind a load balancer |
| Worker | `audit-service worker` | Ingest throughput | ≥1; more is safe |

Separate processes on purpose: a slow WORM archive write never adds latency to an
emitting service's request. Multiple worker replicas are safe — a Redis lease
makes each partition single-writer and the commit re-verifies lease ownership.

### Dependencies that must exist first

| Dependency | Required | Failure mode if missing |
|---|---|---|
| Elasticsearch 9.x | **Yes** | API starts and buffers writes; reads fail |
| Redis 7.x (AOF, noeviction) | **Yes** | Readiness fails; ingest rejected |
| S3 bucket with Object Lock | Yes if `ARCHIVE_ENABLED` | Startup logs `worm_archive_misconfigured`; segments would be deletable |

---

## 1. Build

```bash
docker build -t everycred/audit-service:1.0.0 .
```

Multi-stage on `python:3.14-slim-bookworm`:

- **Builder** installs dependencies with `uv sync --frozen`. `--frozen` fails the
  build if `uv.lock` disagrees with `pyproject.toml`, so an image can never
  silently contain versions that were never tested.
- **Runtime** copies only the virtualenv and `app/`. No compiler, no uv, no build
  cache — a size *and* attack-surface decision.
- Runs as **UID 10001**, non-root, `nologin` shell. The process needs no
  filesystem writes: logs go to stdout, all state lives in ES/Redis/S3.
- `HEALTHCHECK` hits `/health/live` every 15s.
- `ENTRYPOINT ["audit-service"]`, `CMD ["serve"]` — override the command for the
  worker.

Manifests first in the layer order, so the slow dependency layer is cached and
only rebuilt when the manifests change.

---

## 2. Configure

Every setting comes from the environment; `.env.example` is the documented
inventory. Secrets have **no defaults** — the service refuses to start rather
than fall back to a guessable value.

### Secrets (from a secret manager, never an image or repo)

| Variable | Notes |
|---|---|
| `JWT_SECRET_KEY` | Byte-identical to the main backend's `SIGNIN_SECRET_KEY`. HS256 needs ≥32 bytes — enforced at boot |
| `SERVICE_API_KEYS` | Comma-separated for rotation with overlap. `openssl rand -hex 32` |
| `PII_MASTER_KEK` | `audit-service generate-kek`. **Losing it makes all encrypted PII permanently unreadable** |
| `ES_API_KEY` | Scoped key; preferred over `ES_USERNAME`/`ES_PASSWORD` |
| `AWS_*` | Prefer an instance role / IRSA over static keys |

### Required production values

```env
ENVIRONMENT=prod
DEBUG=false
ENABLE_DOCS=false
ES_HOSTS=https://es.internal:9200
ES_VERIFY_CERTS=true
ES_CA_CERT_PATH=/etc/ssl/certs/es-ca.crt
INDEX_REPLICAS=1
CORS_ALLOW_ORIGINS=https://admin.yourdomain.com
ARCHIVE_ENABLED=true
ARCHIVE_BUCKET=everycred-audit-archive-prod
OBJECT_LOCK_MODE=COMPLIANCE
RETENTION_DAYS=2190
```

Eight checks run at boot with `ENVIRONMENT=prod` and **fail the process**:
`DEBUG` off, `ENABLE_DOCS` off, `ES_VERIFY_CERTS` on, `ES_HOSTS` https, CORS not
`*`, `ARCHIVE_BUCKET` set, `OBJECT_LOCK_MODE=COMPLIANCE`, `SERVICE_API_KEYS` set.

A crash-looping pod right after a config change is almost always one of these —
read the startup log, the message names the problem.

### Sizing

| Setting | Guidance |
|---|---|
| `STREAM_PARTITIONS` | 8 default. **Changing it after go-live re-partitions tenants and starts new chains** — plan it as a migration, not a tweak |
| `WORKER_BATCH_SIZE` | 500. Lower for latency, higher for throughput |
| `INGEST_RATE_LIMIT_PER_MINUTE` | Set above peak platform activity — throttling ingest means dropping evidence |
| `READ_RATE_LIMIT_PER_MINUTE` | 120 is deliberately low; reads are the sensitive surface |
| `STREAM_MAX_LEN` | 1 M. A safety valve, not routine — hitting it is data loss and must alert |

---

## 3. Provision infrastructure

### Elasticsearch

See [ELASTICSEARCH_DEPLOYMENT.md](./ELASTICSEARCH_DEPLOYMENT.md). Apply the
least-privilege role and mint an API key before first deploy.

### Redis

```
appendonly yes
appendfsync everysec
maxmemory-policy noeviction
```

**Both matter.** Without AOF, Redis is a buffer rather than a durable queue and
the no-lost-events guarantee does not hold. Without `noeviction`, memory pressure
silently discards queued audit events instead of rejecting the write.

If using ElastiCache, enable AOF (or accept the weaker guarantee explicitly) and
set the eviction policy on the parameter group.

### S3 WORM bucket

Object Lock can **only** be enabled at bucket creation:

```bash
aws s3api create-bucket --bucket everycred-audit-archive-prod \
  --region ap-south-1 --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=ap-south-1

aws s3api put-object-lock-configuration --bucket everycred-audit-archive-prod \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":2190}}}'

aws s3api put-bucket-policy --bucket everycred-audit-archive-prod \
  --policy file://deploy/s3-archive-bucket-policy.json
```

The bucket policy is not optional. Object Lock makes each object *version*
immutable — verified live, a version delete is refused with `WORM protected and
cannot be overwritten` — but it does **not** block a plain `DeleteObject`, which
writes a delete marker and hides the segment from listings. The policy denies
`s3:DeleteObject` so that cannot happen. Full explanation in
[SETUP.md](./SETUP.md#object-lock-is-necessary-but-not-sufficient).

Use a **separate bucket** for Elasticsearch snapshots — those must stay deletable.

---

## 4. Release

### Order matters

```
1. Provision ES + Redis + S3          (once, per environment)
2. Run `audit-service bootstrap`      (idempotent; also runs on API startup)
3. Deploy the API                     (rolling)
4. Deploy the worker                  ── see the warning below ──
5. Point emitters at the service      (dual-write, flag off → on)
```

> ### Drain old workers before starting new ones
>
> This is the most important operational rule in the service.
>
> Worker replicas are safe **within one build**. What is not safe is an *older
> build's* worker running against the same Redis keyspace during a rollout. A
> worker from before the lease-checked commit will chain from a stale head and
> produce `prev_mismatch` breaks that are indistinguishable from tampering in the
> verification report.
>
> Deploy workers with a strategy that **stops old pods before starting new ones**
> — `Recreate` in Kubernetes, or scale to zero and back. A rolling update that
> briefly runs both generations can corrupt chain linkage for the events written
> in that window. Those events remain durable and readable; the chain shows a
> break that has to be explained.
>
> Verify one generation is live:
> ```bash
> docker exec <redis> sh -c 'for i in $(seq 0 7); do redis-cli get "audit:stream:lease:$i"; done' | sort -u
> ```
> One distinct consumer id means one generation.

### Bootstrap in CI/CD

Run it as a pre-deploy job so a template change lands before the code that needs
it:

```bash
audit-service bootstrap
```

Idempotent and safe to run on every deploy.

---

## 5. Reverse proxy

`deploy/nginx/audit.conf` — set `server_name` and the certificate paths.

| Control | Value |
|---|---|
| TLS | 1.2 + 1.3 only; HTTP redirects to HTTPS |
| `client_max_body_size` | `2m` (the app also caps at 5 MiB) |
| Security headers | HSTS, `nosniff`, `DENY`, `no-referrer`, CSP |
| **`/metrics`** | **Denied externally** — scrape it from inside the network |
| `/health*` | Short timeouts, no buffering |
| `/v1/audit/events/export` | `proxy_buffering off`, 600s timeout — exports stream NDJSON |
| `/v1/` | 60s timeout, per-endpoint rate limits |

`proxy_buffering off` on export matters: buffering a million-event NDJSON stream
would defeat the point of streaming it.

---

## 6. Kubernetes notes

The image is a plain 12-factor process; no special operator is needed.

| Concern | Recommendation |
|---|---|
| API deployment | `RollingUpdate`, ≥2 replicas |
| Worker deployment | **`Recreate`** — see the drain warning |
| Liveness probe | `GET /health/live` — checks nothing external, so an ES blip does not restart every pod |
| Readiness probe | `GET /health/ready` — fails on Redis loss; ES loss is reported but tolerated, because the queue absorbs writes |
| Secrets | `Secret` → env, or an external-secrets operator |
| S3 auth | IRSA / workload identity rather than static keys |
| Resources | API: 250m/512Mi request. Worker: 500m/1Gi — it does the crypto and bulk work |
| `terminationGracePeriodSeconds` | ≥40 so a worker can finish its batch and release leases |
| PodDisruptionBudget | On the API; the worker is better served by `Recreate` |

The liveness/readiness asymmetry is deliberate: a liveness probe that failed
during an ES upgrade would restart every replica and turn a degraded read path
into a total outage.

---

## 7. Verify the deploy

```bash
# Liveness and dependency report
curl -s https://audit.yourdomain.com/health/live
curl -s https://audit.yourdomain.com/health   # ES version, queue depth, archive mode

# Ingest and read back
curl -s -X POST https://audit.yourdomain.com/v1/audit/events \
  -H "x-api-key: $KEY" -H "x-audit-tenant-id: $TENANT" \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"action":"credential.issue","event_id":"deploy-check-1",
       "outcome":"success","actor":{"type":"service","id":"deploy-check"},
       "service_name":"deploy-check"}]}'

sleep 3
curl -s https://audit.yourdomain.com/v1/audit/events/deploy-check-1 \
  -H "x-api-key: $KEY" -H "x-audit-tenant-id: $TENANT"

# Integrity gate — exits non-zero on a break
audit-service verify --tenant "$TENANT"
```

Expected: `202` on ingest, the event retrievable within ~1s, and
`intact: True` with a checkpoint once enough events have accumulated.

Startup log lines to confirm:

| Line | Meaning |
|---|---|
| `service_starting` | Config accepted; PII encryption and archive state reported |
| `cluster_bootstrap_complete` | ILM, templates, keyring, streams applied |
| `worm_archive_verified` | Object Lock confirmed on the bucket |
| `worm_archive_misconfigured` | **Segments would be deletable** — fix before trusting the archive |

---

## 8. Monitoring and alerts

Scrape `/metrics` from inside the network.

| Metric | Alert on |
|---|---|
| `audit_queue_total` | Sustained growth — workers are behind |
| `audit_queue_dead_letter_total` | **> 0 — audit events permanently rejected.** Page someone; the DLQ is never trimmed |
| `audit_events_ingested_total{outcome="rejected"}` | A rising ratio means an emitter is sending bad payloads |
| `audit_events_written_total` | Flat while ingest continues — the worker is stuck |
| `audit_events_duplicate_total` | Sustained non-zero means repeated redelivery; check for archive or ES failures |
| `audit_chain_resynced_from_ledger_total` | Expected after a Redis failover; otherwise investigate |

Log lines worth alerting on:

| Line | Severity |
|---|---|
| `commit_refused_lease_lost` | A lease lapsed mid-batch — expected rarely; frequent means Redis latency |
| `batch_was_redelivery_chain_resynced` | Explains a documented gap; frequent means an upstream failure |
| `partition_lease_lost` | Redis connectivity |
| `archive_seal_failed` | Un-notarised evidence; batch retried |
| `keyring_unavailable` | Ingest halted for affected tenants |
| `integrity_verification_failed` | **Security incident** |
| `tenant_mismatch_rejected` | An emitter tried to write into another tenant |
| `worm_archive_misconfigured` | Immutability not actually in place |

Schedule `audit-service verify --tenant <id>` as a job. Continuous verification
is what turns tamper *evidence* into tamper *detection* — a chain checked only
when someone suspects a problem is not much of a control. It exits non-zero on a
break, so it works directly as a cron or CI gate.

---

## 9. Rollback

The service is stateless; the data is not.

| Change | Rollback |
|---|---|
| App code | Redeploy the previous image. **Drain workers first** |
| Config | Revert env and restart |
| Index template | Re-apply the previous template. Existing backing indices keep their mapping; only new ones pick it up |
| ILM policy | Re-apply the previous policy — takes effect on the next phase evaluation |
| `STREAM_PARTITIONS` | **Not a rollback.** Reverting re-partitions tenants again and starts further chains. Treat any change as one-way |

Never delete audit indices to "clean up" a bad deploy. Documents are immutable
and a partial chain is still evidence; a deleted index is a compliance gap.

---

## 10. CI/CD

`.github/workflows/ci.yml` has two jobs:

| Job | Runs | Needs Docker |
|---|---|---|
| `check` | ruff, ruff-format, mypy strict, 261 unit tests, bandit, pip-audit | No |
| `integration` | 24 integration tests against ES 9.2.0 + Redis service containers | Yes |

The integration job is not optional coverage. It verifies guarantees enforced by
Elasticsearch itself and by the worker/Redis/ES interaction — and has already
caught a mapping that broke all pagination and a routing setting that would have
rejected 100% of writes for dedicated tenants.

A release pipeline should add: build and push the image, run `bootstrap` against
the target cluster, deploy the API (rolling), deploy the worker (recreate), then
run the verification in §7.

---

## 11. Emitter cutover

The service is useless until emitters send to it. Recommended sequence:

1. Deploy this service; confirm §7 passes.
2. In `everycred-backend`, set `AUDIT_SERVICE_URL`, `AUDIT_SERVICE_API_KEY`,
   `AUDIT_SERVICE_TIMEOUT_SECONDS=3.0`, and `AUDIT_DUAL_WRITE_ENABLED=false`.
3. Turn dual-write **on**. Legacy tables keep receiving writes, so nothing is
   lost if this service has a problem.
4. Compare counts between the legacy tables and audit search for a period.
5. Backfill history — `audit-service backfill --file <ndjson>`, idempotent on
   legacy row uuids.
6. Migrate readers (admin UI, reports) to the audit API.
7. Only then consider retiring legacy writes.

Emitters should treat audit failures as **non-fatal** for the business
transaction. A credential issuance must not fail because the audit service is
briefly unavailable; the queue and dual-write exist precisely so the audit path
can degrade without taking the platform with it.

---

## Environment matrix

| | Local | Staging | Production |
|---|---|---|---|
| `ENVIRONMENT` | `local` | `staging` | `prod` |
| `ENABLE_DOCS` | `true` | `true` | **`false`** |
| ES nodes / `INDEX_REPLICAS` | 1 / `0` | 1–3 / `0`–`1` | ≥3 / `1` |
| ES security | off | **on** | **on** |
| `ES_HOSTS` | `http://` | `https://` | `https://` |
| Archive | MinIO | S3 (COMPLIANCE) | S3 (COMPLIANCE) |
| Bucket policy | — | applied | **applied** |
| Workers | 1 | 1 | ≥1, `Recreate` |
| `RETENTION_DAYS` | 2190 | 2190 | 2190 |
| Verify job | manual | daily | **daily + alerting** |
