# Security controls

What is implemented to protect this service, why each control exists, and where
it lives in the code. Every claim below corresponds to code in the repository and
to a test.

This service is a high-value target: it holds a queryable record of every action
on the platform, across every tenant, for six years, including personal data. It
is also the thing an attacker would want to edit after a breach. The controls are
organised around those two facts.

- Tech stack: [TECH_STACK.md](./TECH_STACK.md)
- File layout: [FILE_STRUCTURE.md](./FILE_STRUCTURE.md)
- Deployment hardening: [DEPLOYMENT.md](./DEPLOYMENT.md)

---

## Threat model

| # | Threat | Primary control |
|---|---|---|
| T1 | Tenant A reads tenant B's audit trail | Mandatory tenant filter + `constant_keyword` |
| T2 | Attacker edits or deletes records to hide activity | Hash chain + WORM checkpoints + no `delete` privilege |
| T3 | Audit log becomes a PII exfiltration channel | PII encrypted per subject, never indexed |
| T4 | Forged events inserted to mislead an investigation | Tenant reconciliation on ingest; server-assigned integrity |
| T5 | Credential theft (service key / JWT) | Constant-time compare, rotatable keys, scope separation |
| T6 | Reads of the audit trail go unnoticed | Audit-of-the-audit on every search and export |
| T7 | Denial of service via expensive queries | Typed filters only, bounded windows, rate limits |
| T8 | Secrets leak through logs or error responses | Sink-level redaction; no internals in responses |
| T9 | Evidence lost to an infrastructure failure | Durable queue, explicit ack, DLQ |
| T10 | Erasure obligations conflict with immutability | Crypto-shredding |

---

## 1. Authentication

`app/core/security/auth.py`

Two caller types, deliberately distinct:

### Service principal — `x-api-key`

For emitting services that have already enforced RBAC.

- Compared with `hmac.compare_digest` against a **list**, so keys rotate with an
  overlap window (add new → redeploy emitters → drop old).
- The loop always runs to completion, so neither the value nor the *position* of
  a matching key is recoverable from response timing.
- Granted `write`, `read`, `verify`, `export` — deliberately **not** `erase` or
  `cross_tenant`. Destroying personal data and reading across tenants are human
  decisions; a leaked service key must not be able to do either.

### User principal — `Authorization: Bearer <JWT>`

A platform access token, validated with the same secret, issuer and audience as
the main backend, so there is no separate login for this service.

Verified on every request: signature, `exp`, `aud`, `iss`. `options={"require":
["exp", "iat", "sub"]}` forces the claims to be **present**, not merely
consistent — a token without `exp` would otherwise validate forever.

| Attack | Defence | Test |
|---|---|---|
| `alg: none` | Algorithms pinned in `jwt.decode` | `test_unsigned_token_is_rejected` |
| Forged signature | HS256 with the platform secret | `test_invalid_tokens_are_rejected` |
| Token minted for another service | `aud` verified | same |
| Untrusted issuer | `iss` verified | same |
| Non-expiring token | `exp` required | `test_token_without_expiry_is_rejected` |
| Unattributable principal | `sub` must yield a user id | `test_token_without_a_user_identifier_is_rejected` |

A weak HMAC key is a startup failure, not a warning: HS256 requires ≥32 bytes
(RFC 7518 §3.2), enforced in `config.py`. PyJWT only warns; for a service holding
audit evidence that is not enough.

**Both credentials present is rejected**, not resolved by precedence — it is
ambiguous which identity to record in the audit trail, and guessing would make
attribution unreliable.

Rejection messages are deliberately generic (`"token is invalid"`). Echoing the
library's reason back helps an attacker tune a forgery attempt.

---

## 2. Authorisation

`app/domain/enums.py` (`Scope`), enforced in the service layer.

| Scope | Grants |
|---|---|
| `audit:write` | Ingest events |
| `audit:read` | Search, get, aggregate |
| `audit:export` | Bulk export; also permits PII decryption |
| `audit:verify` | Run chain verification |
| `audit:erase` | Crypto-shred a data subject — irreversible |
| `audit:admin` | Tenant administration; implies read/verify/export |
| `audit:cross_tenant` | Query across tenant boundaries — break-glass |

Checks live in services, not routes, so the CLI and worker get the same
enforcement without going through HTTP.

### The secure default for unscoped tokens

An ordinary platform token carries no audit scopes, and this service has no
database access to resolve the platform's RBAC tables. Rather than guess, an
unscoped token is granted exactly one thing: **read access to its own events**,
with `actor_id` pinned in the query scope so the filter cannot be widened.

This is the narrowest useful grant. Guessing wrong in the other direction would
let any logged-in user read their whole tenant's audit trail.

`audit:admin` implies read/verify/export, but **not** `erase` or `cross_tenant` —
both stay explicit.

---

## 3. Tenant isolation

`app/search/query.py` — the isolation boundary.

The cluster runs the **Basic licence**, so there is no document-level security to
fall back on. Isolation is therefore a code invariant, enforced structurally:

1. **Clients never send query DSL.** They send a typed `AuditSearchFilter`; the
   DSL is assembled server-side. Accepting raw DSL would hand callers `script`
   queries, unbounded wildcards and deep aggregations over every tenant's data.
2. **The tenant filter is applied by the builder, not the caller.** `build_query`
   takes a `TenantScope`, and there is no code path that omits it. A scope with
   neither a tenant nor cross-tenant authority cannot even be constructed —
   `TenantScope.__post_init__` raises.
3. **The clause is in `filter` context**, never `should`. A `should` clause is
   optional once another matches, which would make the constraint bypassable.

Additional layers:

| Layer | Control |
|---|---|
| Storage | Dedicated streams map `tenant.id` as `constant_keyword`, so **Elasticsearch itself rejects** a document with the wrong tenant id |
| Index naming | Tenant ids are regex-validated before reaching an index name — rejects `*`, `,`, `..`, spaces and other index-name metacharacters |
| Single-event fetch | `GET /events/{id}` is a filtered **search**, not a document GET, so id-guessing cannot cross a tenant |
| Ingest | A body `tenant_id` may only *confirm* the authenticated tenant, never widen it; a mismatch is logged at error level |
| Cross-tenant | Requires `audit:cross_tenant` and is itself audited as `audit_log.cross_tenant_access` at CRITICAL |

`tests/unit/test_tenant_isolation.py` — 86 tests — asserts the tenant clause is
present, singular and top-level across every filter permutation and pairwise
combination, and that hostile tenant ids are rejected.

---

## 4. Tamper evidence

`app/core/integrity.py`, `app/queue/chain.py`

```
hash_n = SHA256( chain_id ‖ seq_n ‖ hash_{n-1} ‖ canonical_json(doc_n) )
```

Each component is **length-prefixed**, so no boundary-shifting forgery is
possible: with plain concatenation, chain `a` at seq 12 and chain `a1` at seq 2
would share a preimage.

The hash binds the `chain_id`, so a document cannot be lifted from one tenant's
chain into another's and still verify.

| Attack | Detected as |
|---|---|
| Record modified in place | `hash_mismatch` |
| Record deleted | `gap` + `prev_mismatch` |
| Records reordered or inserted | `prev_mismatch` |
| Record replayed | `duplicate_seq` |
| Whole tail rewritten | Contradicts the WORM checkpoint |

Verification continues from the *stored* hash rather than the recomputed one, so
one tampered document does not cascade into a false break on every later record
— which would bury the actual point of failure during an incident.

### Sequence integrity under concurrency

- Reservation is a single Lua script, so two workers can never receive the same
  sequence number.
- A partition is **single-writer**, enforced at three levels: `SET NX EX` lease
  acquisition; the drain loop stopping when the renewer signals loss; and the
  commit re-verifying lease ownership *inside the same Lua script* that moves the
  head. A batch that began while the lease was valid still cannot publish a head
  after losing it.
- Elasticsearch is authoritative. A cold Redis chain is reconciled against the
  ledger rather than restarting at 0 — a reset would look, to a verifier,
  identical to an attacker inserting forged records.

### Immutability at the storage layer

| Control | Effect |
|---|---|
| Data streams | Append-only by design |
| `op_type: create` keyed on event id | A record can never be overwritten; a replay is a 409 |
| ES role has **no `delete`** on audit streams | A compromised service credential cannot destroy evidence — the cluster refuses |
| S3 Object Lock COMPLIANCE | Verified live: a version delete is refused with `WORM protected and cannot be overwritten` |
| Bucket policy denies `s3:DeleteObject` | Object Lock does not stop delete *markers*, which would hide a segment from listings |

---

## 5. Privacy and PII

`app/core/security/crypto.py`

```
PII_MASTER_KEK (env, 32 bytes)
  ├─ HKDF "keyid" → key-id derivation key   (deterministic)
  ├─ HKDF "bidx"  → blind-index key         (optional, off by default)
  └─ AES-GCM wrap → per-subject DEK (random, in the keyring)
                      └─ AES-256-GCM → PII field ciphertext
```

| Control | Rationale |
|---|---|
| **DEKs are random, never derived** | A derived key is recomputable from the KEK, so "deletion" would be theatre |
| AES-256-GCM, 96-bit random nonce | The only nonce size NIST optimises for and the only one safe with random generation at scale |
| **AAD = `<event_id>|<field_path>`** | A ciphertext lifted into another event or field fails authentication instead of silently decrypting to someone else's data |
| HKDF purpose separation | A weakness in one use (blind index) cannot be pivoted into another (field encryption) |
| Key ids are keyed HMAC | Reading the keyring index does not enumerate users |
| Key ids are tenant-scoped | Identical subject ids in two tenants never share a key |
| PII stored in `pii_ct`, mapped `enabled: false` | Not indexed at all: no inverted index, no doc values, unsearchable and unaggregatable. Verified live — a term query returns 0 hits |
| PII fields absent from the mapping | A future emitter writing plaintext to `actor.email` is rejected by `dynamic: strict` rather than quietly indexing it |
| `source.ip` → `source.ip_prefix` (/24, /48) | Network analytics without retaining an address that identifies a person |
| Decryption gated on `audit:export`/`audit:admin` | Most audit review needs no personal data; a caller without the scope sees `[PROTECTED]` markers |

Search is by stable non-PII identifiers (`actor.id`, `target.id`, `session_id`) —
which is what a DSR or an investigation actually starts from.

### Erasure without breaking immutability

GDPR Art. 17 and DPDP s.12 grant erasure; SOC 2, ISO 27001 and HIPAA 164.312(b)
demand immutability. Crypto-shredding resolves the conflict: **destroy the key,
keep the record.**

Verified end-to-end against the live service. After erasing a subject:

| Field | Before | After |
|---|---|---|
| `actor.email`, `actor.name`, `source.ip` | plaintext | `[ERASED]` |
| `actor.id`, `target.id`, `event.outcome`, `source.ip_prefix` | present | **unchanged** |
| Chain verification | `intact: True` | **`intact: True`** |

The chain survives because the hash is computed over the **ciphertext**. The
stored bytes never change; only the key needed to read them is destroyed.

Supporting properties:

- The keyring keeps a **tombstone**, so a reader can distinguish "erased on
  request" from "never existed" — a distinction auditors ask about.
- A shredded key **cannot be recreated** for new writes; otherwise a later event
  would silently undo the erasure.
- Erasure is **idempotent** — a repeated DSR is not an error.
- It is **surgical**: other subjects are unaffected.
- The erasure is itself audited at CRITICAL severity with the legal basis and DSR
  reference, and the count of affected records is returned for GDPR Art. 19.

---

## 6. Secret handling

| Control | Where |
|---|---|
| No default secrets — the service refuses to start | `core/config.py` |
| Secrets typed `SecretStr`, so a stray f-string prints `**********` | `core/config.py` |
| 33 credential-shaped keys redacted from `labels` and `change` diffs at the API boundary | `domain/events.py` → `REDACT_KEYS` |
| Redaction at the **log sink**, not the call site | `core/logging.py` |
| Substring matching catches `db_password`, `jwt_secret_key`, `api_key_value` | `core/logging.py` |
| Redaction is depth-bounded | A cyclic or hostile payload cannot turn a log call into a stack overflow |
| `Principal.claims` excluded from `repr` | Token claims cannot reach a log line accidentally |
| Rate-limit keys hash the credential | The raw key never appears in Redis, visible to `MONITOR` or a keyspace dump |

Redaction lives at the sink because secrets leak into logs by accident far more
often than through the intended data path.

---

## 7. Input validation and DoS resistance

| Control | Value |
|---|---|
| Raw ES DSL from clients | **Never accepted** |
| `extra="forbid"` on every wire model | A typo is a 422 now, not a missing field in an incident |
| Bounded string lengths on all keyword fields | An unbounded `keyword` is a mapping-explosion and memory risk |
| Time window required and capped | `MAX_QUERY_WINDOW_DAYS=400`; unbounded means a six-year scan |
| Page size cap | `MAX_PAGE_SIZE=200` |
| Total-hit counting capped | `TOTAL_HITS_CAP=10_000` |
| `group_by` allow-list | An arbitrary field would let a caller exhaust cluster heap |
| `_source` field allow-list | `pii_ct` can never be requested directly |
| Ingest batch cap | `MAX_INGEST_BATCH_SIZE=500` |
| Request body cap | 5 MiB, checked on `Content-Length` before the body is read |
| `target.ids` cap | 1,000 per bulk event |
| `label_terms` cap | 20 clauses |
| Rate limits | 120/min reads, 20,000/min ingest, per principal, cluster-wide via Redis |
| Mapping field limit | 200 — an accidental explosion becomes an immediate error |
| `flattened` for free-form subtrees | Fixed mapping cost instead of unbounded field growth |

Rate limits are asymmetric on purpose: reads are the sensitive surface and get a
low ceiling; ingest is trusted machine traffic and gets a high one, because
throttling ingest means dropping audit evidence.

The rate limiter **fails open** if Redis is unreachable — blocking audit writes
to protect against a load problem is the wrong trade — but logs the failure at
error level.

---

## 8. Transport and HTTP hardening

Set by `core/middleware/stack.py` on every response:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Cache-Control` / `Pragma` | `no-store, no-cache, must-revalidate` / `no-cache` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (production only) |
| `Server` | `audit` — no version disclosure |

`no-store` matters: audit responses contain personal data and no cache may retain
them. HSTS is production-only, because on a local HTTP origin it would pin the
browser to `https://localhost`.

Other transport controls:

- **CORS defaults to empty.** The main backend's broad `allow_origins=["*"]` is
  deliberately not copied here, because these endpoints return cross-user
  personal data. `*` is rejected outright in production.
- Only `GET`, `POST`, `OPTIONS` allowed — audit records are never updated or
  deleted.
- **TLS to Elasticsearch** verified against a pinned CA, TLS 1.2 minimum;
  disabling verification is blocked in production.
- ES **API-key auth preferred** over basic auth: scoped, revocable, no reusable
  password on the wire.
- nginx (`deploy/nginx/audit.conf`): TLS 1.2/1.3, `client_max_body_size 2m`,
  duplicate security headers, and **`/metrics` denied externally**.
- Inbound `x-request-id` is sanitised and length-capped — it is attacker-
  controlled and ends up in log lines, where an unbounded value invites log
  injection.

---

## 9. Audit-of-the-audit

HIPAA 164.312(b) and SOC 2 CC7.2 require access to the audit trail to itself be
logged. A reader who can search without leaving a trace defeats the purpose.

`app/services/query_service.py` emits an audit event for every:

| Action | Severity |
|---|---|
| `audit_log.search` | INFO |
| `audit_log.export` | HIGH — recorded **before** streaming starts, so an aborted download still leaves evidence |
| `audit_log.integrity_verify` | INFO |
| `audit_log.erasure_request` | CRITICAL |
| `audit_log.cross_tenant_access` | CRITICAL |

Each records the principal, whether a service acted on behalf of a human, the
result count and whether the read was self-restricted.

These writes are best-effort and swallow failures — mirroring the main backend's
`AuditLogService` — because a problem recording the meta-event must not fail the
caller's query. The one exception is **erasure**, where the failure is *not*
swallowed: an unrecorded erasure is an undocumented destruction of evidence.

---

## 10. Error handling

`app/core/exceptions.py`

A client learns *what to fix*, never *how the service is built*. Stack traces,
Elasticsearch error bodies, index names and query DSL all stay server-side: on a
service holding every tenant's audit trail, an error message is a reconnaissance
channel.

| Situation | Client sees | Server logs |
|---|---|---|
| Auth failure | `401` + `WWW-Authenticate` | Reason, path, request id |
| Missing scope | `403` with the missing scope named | Full context |
| ES rejection | `502`, generic | ES error type and reason |
| ES unreachable | `503`, generic | Transport error |
| Keyring unavailable | `503` "not recorded" | Full error |
| Unhandled | `500` + a reference id | Full traceback |

The missing scope *is* returned — the caller is already authenticated, and
knowing which grant they lack is what lets them request it.

---

## 11. Supply chain and runtime

| Control | Detail |
|---|---|
| `uv.lock` committed; CI uses `--frozen` | A build fails rather than resolving untested versions |
| `pip-audit` in CI | Dependency CVE scan; currently no known vulnerabilities |
| `bandit` in CI | SAST; currently no findings. Two suppressions, both justified in-line |
| `mypy --strict` | A mistyped tenant filter is a data-leak bug |
| ES client major pinned | `>=9,<10` — must match the cluster |
| Container runs as **UID 10001**, non-root | No filesystem writes needed; state lives in ES/Redis/S3 |
| Multi-stage build | No compiler, no uv, no build cache in the runtime image |
| uv pinned by digest-able tag | `ghcr.io/astral-sh/uv:0.9.7`, not pip-installed |
| `nologin` shell for the service account | — |

---

## 12. Least privilege

### Elasticsearch role (`elasticsearch/audit-service-role.json`)

| Target | Privileges | Notably absent |
|---|---|---|
| Audit data streams | `create_doc`, `create_index`, `read`, `view_index_metadata`, `monitor`, `manage` | **`delete`, `write`** |
| `audit-keyring-v1` | `create_index`, `read`, `write`, `delete`, `view_index_metadata` | — |
| Cluster | `monitor`, `manage_ilm`, `manage_index_templates` | — |

`create_doc` permits indexing new documents but **not** overwriting an existing
one — the storage-layer expression of an append-only log. `write` is withheld
because it would permit update and delete on audit records.

`delete` is granted on the keyring **and only there**: that single deletion is
the entire crypto-shredding mechanism.

### S3 bucket policy (`deploy/s3-archive-bucket-policy.json`)

Denies `s3:DeleteObject` and `s3:DeleteObjectVersion`; denies retention and
legal-hold tampering and `PutBucketVersioning`; denies non-TLS access; restricts
`PutObject` to the audit writer role — anyone else writing there could plant a
permanently undeletable object.

---

## Compliance mapping

| Requirement | Control |
|---|---|
| SOC 2 CC6.1 — no default credentials | Boot-time validation, no secret defaults |
| SOC 2 CC7.2 / HIPAA 164.312(b) — audit the audit | Every read and export emits `audit_log.*` |
| ISO 27001 A.12.4 — protected, immutable logs | Data streams + hash chain + Object Lock |
| HIPAA 164.312(a) — access control | Scope model, tenant isolation, least-privilege ES role |
| HIPAA 164.312(e) — transmission security | TLS to ES and S3, HSTS, nginx TLS 1.2+ |
| HIPAA 164.316(b)(2)(i) — 6-year retention | `RETENTION_DAYS=2190`, ILM delete phase |
| GDPR Art. 17 / DPDP s.12 — erasure | Crypto-shredding |
| GDPR Art. 19 — report affected records | `ErasureReceipt.affected_events` |
| GDPR Art. 5(1)(c) — minimisation | PII never indexed; IP truncated to a prefix |
| GDPR Art. 32 — encryption | AES-256-GCM per subject, at rest |
| DPDP s.8(5) — accuracy of records | Insert-only; duplicate event ids rejected |

The ILM delete phase is the *regulatory maximum* retention, not the erasure
mechanism. Deleting a record early would break the chain and destroy evidence.

---

## Known residual risks

Stated explicitly rather than left implicit.

| Risk | Status |
|---|---|
| **`PII_MASTER_KEK` loss** makes all encrypted PII permanently unreadable | By design — there is no recovery path. Store in a secret manager with backup |
| **The keyring index is a single point of failure** for PII readability | Must be in the snapshot policy. Holds only *wrapped* keys, so a stolen copy is still gated by the KEK |
| **Snapshots taken before an erasure still contain the destroyed key** | Keep snapshot retention as short as the recovery objective allows; document the window in the DPIA |
| **A service key grants `audit:export`**, hence PII decryption | Necessary for the backend to render logs to authorised users. It cannot `erase` or read cross-tenant. Rotate on suspicion |
| **No document-level security** (Basic licence) | Isolation is a code invariant with 86 dedicated tests. A licence upgrade would add defence in depth |
| **Optional blind index survives crypto-shredding** | Off by default. Enabling it retains a "was this email present?" oracle for KEK holders — pseudonymisation, not erasure |
| **Rate limiter fails open** on a Redis outage | Deliberate: losing audit evidence is worse than a load spike. Logged at error level |
| **An older worker build against the same Redis keyspace** can produce chain breaks | Operational: drain and stop old workers before starting new ones. Documented in SETUP.md |

---

## Verification

| Control area | Evidence |
|---|---|
| Tenant isolation | `tests/unit/test_tenant_isolation.py` — 86 tests, every filter permutation |
| Tamper evidence | `tests/unit/test_integrity.py` — one test per attack class |
| Crypto-shredding | `tests/unit/test_crypto_shredding.py` — incl. chain intact after erasure |
| Authentication | `tests/unit/test_auth.py` — incl. `alg: none`, missing `exp` |
| Sequence integrity | `tests/unit/test_chain_allocator.py` — 50 concurrent reservations, lease loss |
| Storage-enforced isolation | `tests/integration/test_end_to_end.py` — `constant_keyword` rejection |
| Ciphertext unsearchable | same — term query on `pii_ct` returns 0 hits |
| Pipeline integrity | `tests/integration/test_worker_pipeline.py` — real worker |
| WORM immutability | Verified live: `WORM protected and cannot be overwritten` |
| Erasure | Verified live: PII `[ERASED]`, chain `intact: True` |

Run the security gate:

```bash
uv run bandit -c pyproject.toml -r app
uv run pip-audit
uv run mypy app
uv run pytest
```

## Reporting

Security issues in this service should go through the platform's existing
disclosure process. Include the request id from the response — it correlates to
the full server-side context in the structured logs.
