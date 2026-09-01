# Elasticsearch deployment

Provisioning, sizing, hardening and operating the audit cluster.

This is the platform's **first** Elasticsearch deployment — no existing cluster
was reused, so everything here is greenfield.

- Tech stack: [TECH_STACK.md](./TECH_STACK.md)
- Security: [SECURITY.md](./SECURITY.md)
- Service deployment: [DEPLOYMENT.md](./DEPLOYMENT.md)

---

## Version and licence

| Item | Value |
|---|---|
| Server | **Elasticsearch 9.2.0** |
| Client | `elasticsearch[async]` 9.5.0, pinned `>=9,<10` |
| Licence | **Basic** (free) |
| Deployment | Self-hosted (Docker / Kubernetes) |

The client refuses to talk to a cluster of a different major version, so the pin
is a correctness constraint. `app/search/client.py` logs
`elasticsearch_version_mismatch` at startup if the cluster major is not 9 — a
silent mismatch would otherwise surface as confusing query-time errors.

### What Basic does not include

**No document-level or field-level security.** Tenant isolation is therefore a
code invariant enforced in `app/search/query.py`, backed by 86 tests, plus
`constant_keyword` enforcement at the storage layer for dedicated streams. See
[SECURITY.md §3](./SECURITY.md#3-tenant-isolation).

If the organisation later buys Platinum, DLS-backed roles become available as
defence in depth. The code does not depend on that happening.

### ES 9 breaking change to know

`xpack.ilm.enabled` **was removed in 9.x** — ILM is always on. Passing it makes
the node refuse to boot:

```
unknown setting [xpack.ilm.enabled] did you mean any of [xpack.ml.enabled, ...]
```

This was hit during development and is fixed in `docker-compose.yml`. Watch for
it in any hand-written Helm values or systemd unit.

---

## Topology

```
                    ┌──────────────────────────────────────────┐
   ILM policy       │  audit-retention                         │
                    │  hot → warm(30d) → cold(180d) → del(2190d)│
                    └──────────────────────────────────────────┘
                                    │ referenced by
        ┌───────────────────────────┴───────────────────────────┐
        ▼                                                       ▼
┌───────────────────────────┐                 ┌───────────────────────────────┐
│ template: audit-shared    │ priority 200    │ template: audit-dedicated     │ priority 300
│ pattern:  audit-shared    │                 │ pattern:  audit-t-*           │
│ tenant.id: keyword        │                 │ tenant.id: constant_keyword   │
│ shards: 3                 │                 │ shards: 1                     │
│ allow_custom_routing: true│                 │ allow_custom_routing: FALSE   │
└───────────┬───────────────┘                 └───────────┬───────────────────┘
            ▼                                             ▼
   data stream: audit-shared                  data stream: audit-t-<tenant>
   .ds-audit-shared-YYYY.MM.DD-NNNNNN         .ds-audit-t-<tenant>-...

┌────────────────────────────────────────────────────────────────┐
│ audit-keyring-v1   normal index, 1 shard, MUTABLE              │
│ wrapped per-subject DEKs — deleting from here IS the erasure   │
└────────────────────────────────────────────────────────────────┘
```

Names derive from `INDEX_PREFIX`, so two deployments can share a cluster without
colliding. **Template names too** — a hardcoded name meant an integration run
clobbered the staging template and ES rejected it with *"would cause data streams
to no longer match a data stream template"*.

### Hybrid tenant isolation

| | Shared stream | Dedicated stream |
|---|---|---|
| Name | `audit-shared` | `audit-t-<tenant>` |
| Used by | Every tenant by default | Tenants in `DEDICATED_TENANTS` |
| `tenant.id` mapping | `keyword` | `constant_keyword` |
| Shards | 3 | 1 |
| Custom routing | Yes — routed by `tenant.id` | **No** |
| Isolation | Mandatory query filter | Filter **+ ES rejects wrong-tenant docs** |

`constant_keyword` is the strong guarantee: a backing index adopts the tenant id
of its first document, and any later document with a different value is rejected
by Elasticsearch with `document_parsing_exception`. Cross-tenant contamination
becomes impossible rather than merely unlikely.

Custom routing pins a shared-stream tenant to **one shard**, so its searches fan
out to one shard instead of three.

> **Do not enable `allow_custom_routing` on the dedicated template.** Enabling it
> makes ES set `_routing: {required: true}` on every backing index, and the router
> supplies no routing key for a dedicated tenant — every write then fails with
> `routing_missing_exception`. This was a real bug: it would have rejected 100% of
> writes for exactly the highest-volume tenants.
> `test_dedicated_stream_does_not_require_routing` locks the behaviour in.

### Promoting a tenant

```bash
# 1. Provision the stream (off the write path)
curl -X POST "$AUDIT_URL/v1/audit/admin/tenants/$TENANT/dedicate" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# 2. Add to DEDICATED_TENANTS and restart the service + workers
```

Promotion is **non-destructive**: reads cover the dedicated stream *and* the
shared one, so history written before promotion stays visible. Routing is a
config change on purpose — index topology should be reviewable in version
control, not mutable at runtime.

---

## Mapping

Root `dynamic: strict`. 13 top-level fields, `total_fields.limit: 200`.

| Field | Type | Notes |
|---|---|---|
| `@timestamp` | `date` | Index-sorted descending |
| `event.*` | `keyword` ×6, `date` | `id` is **sortable** (see below) |
| `tenant.*` | `keyword` ×3 | `id` is `constant_keyword` on dedicated |
| `actor.*` | `keyword`, `long` | **No email/name/phone** — PII by design |
| `target.*` | `keyword`, `long` | `ids` for bulk events |
| `source.*` | `keyword` | **`ip_prefix` only** — no full IP |
| `http.*` | `keyword`, `short`, `float` | |
| `change.*` | `keyword`, **`flattened`** ×2 | before/after diffs |
| `service.*` | `keyword` ×2 | |
| `message` | `match_only_text` | Log-optimised; ~10% smaller than `text` |
| `labels` | **`flattened`** | Free-form emitter context |
| `integrity.*` | `long`, `keyword` ×4 | Hash chain |
| `pii.*` | `boolean`, `keyword`, `short`, `date` | Key pointer + tombstone |
| `pii_ct` | `object`, **`enabled: false`** | Ciphertext: stored, never indexed |

### Why these choices

**`dynamic: strict`** — an unmapped field is a hard indexing error, not a
silently unsearchable one. Rejected documents go to the dead-letter queue and
raise an alert, so the failure is loud instead of being discovered during an
incident. Free-form data has a home: `labels`.

**`flattened`** for `labels` and `change.before/after` — these hold arbitrary
business fields. As objects they would be a mapping explosion: one emitter
logging a per-record diff could add thousands of fields and eventually break the
cluster. `flattened` indexes the subtree as one field: still queryable by exact
key/value, at fixed mapping cost.

**`pii_ct` with `enabled: false`** — no inverted index, no doc values. Encrypted
blobs cannot be searched or aggregated, so there is no oracle over personal data.
Verified live: a term query on `pii_ct.actor.email` returns 0 hits.

**PII fields absent entirely** — `actor.email` is not in the mapping, so a future
emitter writing plaintext there is rejected by `dynamic: strict` rather than
quietly indexing personal data.

**`doc_values: false` on filter-only identifiers** — `integrity.hash`,
`prev_hash`, `target.ids`, `http.request_id`, `pii.key_id`. Meaningful disk saving
on the widest fields.

> **`event.id` keeps doc values.** It looks like a filter-only identifier but is
> the `search_after` sort tiebreaker, and sorting reads doc values. Dropping them
> made **every paginated search** fail with
> `Can't load fielddata on [event.id]`. Found by integration test, not review.

### Index settings

| Setting | Value | Why |
|---|---|---|
| `sort.field` / `order` | `@timestamp` / `desc` | Newest-first is the dominant query; lets Lucene terminate early |
| `codec` | `best_compression` | Write-once, read-rarely: ~20–30% less disk for a little decompression CPU |
| `refresh_interval` | `1s` | Much cheaper indexing than the 200ms default under bulk load |
| `number_of_routing_shards` | 30 | Allows a later `shrink` to any divisor without a reindex |
| `mapping.total_fields.limit` | 200 | Strict mapping bounds the count; a low ceiling turns an explosion into an error |
| `mapping.ignore_malformed` | `false` | A malformed value must fail, not be silently dropped |

---

## ILM policy — `audit-retention`

| Phase | `min_age` | Actions |
|---|---|---|
| **hot** | — | `rollover` (50 GB primary shard **or** 30 d), `set_priority: 100` |
| **warm** | 30 d | `forcemerge` → 1 segment, `readonly`, `set_priority: 50` |
| **cold** | 180 d | `allocate` replicas → **0**, `set_priority: 0` |
| **delete** | **2190 d** | `delete` |

2,190 days = 6 years, the HIPAA 164.316(b)(2)(i) floor.

`forcemerge` + `readonly` in warm gives the best search latency and disk footprint
for immutable data. Cold drops replicas because durability there comes from the
S3 WORM archive and cluster snapshots — paying for a second copy of five-year-old
data is waste.

> **The delete phase is the regulatory *maximum* retention, not the erasure
> mechanism.** Erasure requests are served by crypto-shredding, which leaves the
> record in place. Deleting a record early would break the hash chain and destroy
> audit evidence.

---

## Provisioning

Everything is declarative and idempotent in `app/search/mappings.py`, applied by
`app/search/bootstrap.py`.

```bash
uv run audit-service bootstrap
```

Also runs automatically on API startup. Order is not incidental: the ILM policy
must exist before a template references it, and the template must exist before
the first document creates a data stream — a stream created without a template
gets dynamic mapping, which would defeat `dynamic: strict` and quietly index PII.

It creates: ILM policy → shared template → dedicated template → keyring index →
data streams.

### Two provisioning traps

**1. `GET /_data_stream/<name>` returns HTTP 200 with an empty list** for a
missing stream in ES 9.x, not a 404. Relying on `NotFoundError` alone reports
every missing stream as already present, so nothing is ever created. The check
inspects the response body.

**2. A concrete index blocks the data stream of the same name.** If a write
reaches the cluster before the template does, ES auto-creates a plain index. It
can never be converted, and ES reports the conflict as an opaque 500
(`illegal_state_exception`). `bootstrap` detects it and raises an actionable
message instead:

```
a concrete index named 'audit-shared' exists, which blocks creating the data
stream of the same name. ... DELETE /audit-shared and re-run bootstrap.
```

---

## Sizing

### Per-node

| Setting | Guidance |
|---|---|
| Heap | 50% of container memory, **never above ~31 GB** — past that the JVM loses compressed oops and effective heap goes *down* |
| `bootstrap.memory_lock` | `true`; matching `memlock` ulimit unlimited |
| File descriptors | ≥65,536 |
| Storage | SSD/NVMe for hot; HDD acceptable for cold |
| `vm.max_map_count` | ≥262,144 on the host |

### Cluster shape

| Environment | Nodes | `INDEX_REPLICAS` | Notes |
|---|---|---|---|
| Local | 1 | **0** | A single node cannot allocate replicas; leaving it at 1 pins the cluster yellow forever |
| Staging | 1–3 | 0–1 | |
| Production | ≥3 (dedicated masters) | **1** | 3 masters avoid split brain |

Health is `yellow` on a single node by design — replicas are unassignable. The
compose healthcheck waits for `yellow`, not `green`, or it would hang forever.

### Capacity

Rough per-event stored size, `best_compression`, no large `change` diffs:

| Component | Approx |
|---|---|
| `_source` | 0.6–1.2 KB |
| Indexed structures | 0.2–0.4 KB |
| **Total** | **~1–1.5 KB/event** |

| Events/day | ~Daily | ~6 years (1 replica) |
|---|---|---|
| 100 K | 150 MB | ~640 GB |
| 1 M | 1.5 GB | ~6.4 TB |
| 10 M | 15 GB | ~64 TB |

Warm-phase `forcemerge` reduces this; cold-phase replica removal roughly halves
the tail. Measure against your own event mix before committing budget — a
`credential.issue.bulk` event with 1,000 `target.ids` is far larger than a login.

Rollover at 50 GB primary shard size keeps shards in the recommended 20–50 GB
band. At 10 M events/day, consider raising `SHARED_SHARD_COUNT` and promoting
heavy tenants to dedicated streams.

---

## Security hardening

Local compose runs with `xpack.security.enabled=false` for convenience. **Never
in production** — and the service enforces it: an `http://` host with
`ENVIRONMENT=prod` fails the boot.

### Checklist

- [ ] `xpack.security.enabled: true`
- [ ] TLS on HTTP **and** transport; `ES_CA_CERT_PATH` set, `ES_VERIFY_CERTS=true`
- [ ] Authenticate with a scoped **API key** (`ES_API_KEY`), not basic auth
- [ ] Apply the least-privilege role below
- [ ] Cluster not reachable from the internet; only the audit service and ops
- [ ] Audit logging enabled on the cluster itself
- [ ] Snapshot policy covering **`audit-keyring-v1`**
- [ ] Encryption at rest at the volume/disk layer

### Role and API key

Apply `elasticsearch/audit-service-role.json`:

```bash
curl -X PUT "$ES/_security/role/audit_service" -H 'Content-Type: application/json' \
  -d "$(python -c "import json;print(json.dumps(json.load(open('elasticsearch/audit-service-role.json'))['role']))")"

curl -X POST "$ES/_security/api_key" -H 'Content-Type: application/json' -d '{
  "name": "audit-service",
  "role_descriptors": { "audit_service": { "cluster": ["monitor","manage_ilm","manage_index_templates"] } }
}'
```

| Target | Privileges | Deliberately absent |
|---|---|---|
| Audit streams + `.ds-audit-*` | `create_doc`, `create_index`, `read`, `view_index_metadata`, `monitor`, `manage` | **`delete`, `write`** |
| `audit-keyring-v1` | `create_index`, `read`, `write`, `delete`, `view_index_metadata` | — |
| Cluster | `monitor`, `manage_ilm`, `manage_index_templates` | — |

`create_doc` allows indexing new documents but **not** overwriting one — the
storage-layer expression of append-only. `write` is withheld because it permits
update and delete. So a compromised service credential **cannot destroy audit
evidence**: the cluster refuses, rather than the application merely not asking.

`delete` is granted on the keyring and only there — that single deletion is the
whole crypto-shredding mechanism.

Backing indices (`.ds-audit-*`) must be listed: ILM and point-in-time address
them directly, not through the data stream alias.

---

## The keyring index

Deliberately **not** a data stream: erasure must delete from it.

```
audit-keyring-v1   1 shard, best_compression, dynamic: strict
  wrapped (keyword, index=false, doc_values=false)   base64 wrapped DEK
  kek_version (short) · created_at (date)
  shredded (boolean) · shredded_at (date)
  shred_reason (keyword) · shred_request_id (keyword)
```

`wrapped` is not indexed — it is only ever fetched by document id.

**Operational consequences:**

- It is the **single point of failure for PII readability**. Lose it and every
  encrypted field is unreadable forever. It must be in the snapshot policy with
  retention ≥ `RETENTION_DAYS`.
- It holds only *wrapped* keys, so a stolen copy is still gated by
  `PII_MASTER_KEK`, which lives outside the cluster.
- It is **never archived to WORM**. Writing key material somewhere undeletable
  would make it permanently recoverable and defeat crypto-shredding outright.
- **A snapshot taken before an erasure still contains the destroyed key.**
  Snapshot retention is therefore itself a GDPR consideration: keep it as short
  as the recovery objective allows and document the window in the DPIA.

---

## Query performance

Measures that matter at six-year scale (all in `app/search/query.py` and
`repository.py`):

| Measure | Effect |
|---|---|
| Custom routing by `tenant.id` | Tenant search hits **1 shard**, not all |
| `index.sort` `@timestamp` desc | Lucene terminates early on newest-first |
| Filter context only | No scoring; results cacheable in the node query cache |
| `track_total_hits: false` | Skips counting every match across the retention window |
| `search_after` + PIT | Page 500 costs the same as page 1; `from: 10000` would sort and discard 10,000 docs *per shard* |
| `pre_filter_shard_size: 1` | Skips backing indices whose date range cannot match — the biggest win for a narrow window over years of indices |
| `constant_keyword` on dedicated | Tenant filter resolved at query-rewrite time |
| `_source` allow-list | Less decompression on wide `change` diffs |
| `execution_hint: global_ordinals` | Right hint for low-cardinality keyword terms aggs |
| `allow_partial_search_results: false` | A partial result set in a compliance report is worse than an explicit failure |

Guardrails: unbounded time ranges refused (`MAX_QUERY_WINDOW_DAYS=400`), page
size capped at 200, total-hits capped at 10,000, `group_by` restricted to an
allow-list, and **raw DSL never accepted** from clients.

---

## Operations

### Monitoring

| Signal | Meaning |
|---|---|
| Cluster health | `yellow` expected on 1 node; investigate on ≥3 |
| ILM errors | `GET _ilm/explain` — a stuck phase means retention is not running |
| Rejected bulk items | Mapping conflicts; correlate with the DLQ |
| Heap pressure / GC | Sustained >75% old-gen after GC needs more nodes |
| Shard count per node | Keep well under 1,000; each shard carries overhead |
| `elasticsearch_version_mismatch` | Client/cluster major mismatch |

### Useful commands

```bash
# Health and ILM
curl -s "$ES/_cluster/health?pretty"
curl -s "$ES/_ilm/explain?pretty" | head -40

# What the service created
curl -s "$ES/_index_template/audit-*?pretty" | grep -E '"name"|index_patterns'
curl -s "$ES/_data_stream/audit-*?pretty" | grep -E '"name"|index_name'
curl -s "$ES/_cat/indices/.ds-audit-*?v&h=index,docs.count,store.size,pri,rep"

# Integrity gate (exits non-zero on a break)
uv run audit-service verify --tenant <tenant-id>
```

### Snapshots

The S3 WORM archive is the durability story for audit *segments*. Snapshots still
matter for two reasons: `audit-keyring-v1` exists **only** in Elasticsearch, and
restoring from the archive means replaying millions of documents where a snapshot
restore is hours faster.

```bash
curl -X PUT "$ES/_snapshot/audit_repo" -H 'Content-Type: application/json' -d '{
  "type": "s3",
  "settings": { "bucket": "everycred-es-snapshots", "region": "ap-south-1" }
}'
```

Use a **different bucket** from the WORM archive — snapshots must remain
deletable, and the archive bucket denies deletion.

### Upgrades

1. Read the 9.x → next breaking changes; assume settings get removed (see
   `xpack.ilm.enabled`).
2. Bump `elasticsearch` in `pyproject.toml` **in the same change** as the server
   — the major must match.
3. Snapshot first, including the keyring.
4. Rolling restart; wait for `yellow`/`green` between nodes.
5. Run `uv run pytest -m integration` against the upgraded cluster. Those tests
   verify guarantees enforced by ES itself and have already caught mapping and
   routing regressions.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unknown setting [xpack.ilm.enabled]` | Removed in ES 9 | Drop the setting |
| Cluster stuck yellow | `INDEX_REPLICAS=1` on one node | Set `0` for single-node |
| `Can't load fielddata on [event.id]` | A sort field lost `doc_values` | Restore doc values on sort fields |
| `routing_missing_exception` on a dedicated stream | `allow_custom_routing` enabled there | Remove it from the dedicated template |
| `strict_dynamic_mapping_exception` | Emitter sent an undeclared field | Add it to `mappings.py` **and** the event model, or move it under `labels` |
| `document_parsing_exception ... constant_keyword` | Wrong-tenant document to a dedicated stream | A routing bug — isolation working as intended |
| `would cause data streams to no longer match a template` | Template name reused with a different pattern | Template names derive from `INDEX_PREFIX`; use a distinct prefix |
| `illegal_state_exception ... conflicts with index` | Concrete index occupying a stream name | Delete it and re-run bootstrap |
| Searches slow on a narrow window | `pre_filter_shard_size` not applied, or no routing | Verify the repository path is used, not a hand-rolled query |
