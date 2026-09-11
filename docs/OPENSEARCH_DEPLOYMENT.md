# OpenSearch deployment

The sibling of [`ELASTICSEARCH_DEPLOYMENT.md`](ELASTICSEARCH_DEPLOYMENT.md). Read
that one for the topology, mapping and index-settings reasoning — all of it
applies here. This document covers only what is different when
`SEARCH_BACKEND=opensearch`, and how to stand up a managed AWS domain.

## Version and support

| Item | Value |
|---|---|
| Server | **OpenSearch 2.x** (managed AWS domain or self-hosted) |
| Client | `opensearch-py[async]`, pinned `>=2.8,<3` |
| Adapter | `app/search/backends/opensearch.py` |
| Serverless collections | **Not supported** — see below |

The client is deliberately held below 3.0: `opensearch-py` 3.x pulls `grpcio`
and `protobuf` for a gRPC transport this service does not use, and an audit
store is the wrong place to add native dependencies for nothing.

**OpenSearch Serverless is not supported.** A collection restricts the admin
APIs this service provisions with — index templates, ISM, point-in-time — so
bootstrap cannot apply the topology. Use a managed domain.

## What differs from Elasticsearch

Everything in the request path is identical: the query DSL, `search_after`
pagination, bulk writes, `op_type: create` idempotency, and every field type
except three. Four things differ, and all four live inside the adapter.

| | Elasticsearch | OpenSearch |
|---|---|---|
| Retention | ILM (`_ilm/policy`), attached per index by `index.lifecycle.name` | ISM (`_plugins/_ism/policies`), attached by `ism_template` index patterns |
| `labels`, `change.before/after` | `flattened` | `flat_object` |
| `message` | `match_only_text` | `text` |
| `user.uuid` on a dedicated stream | `constant_keyword` | `keyword` — see [User isolation](#user-isolation) |
| Point-in-time | `open_point_in_time` → `id`, `ignore_unavailable` supported | `create_pit` → `pit_id`; no `ignore_unavailable`, so a missing target is a clean `index_not_found_exception` rather than an empty PIT |
| Custom routing on a data stream | Supported via `allow_custom_routing` | **Rejected outright** — see below |
| `@timestamp` sort | Takes a `format`, so the cursor carries a formatted date | `field_sort` rejects `format`; the cursor carries epoch millis |
| Auth | API key or basic | Basic (fine-grained access control) or SigV4 |

### Custom routing

This one has an operational consequence rather than just a code one. On
Elasticsearch the shared stream routes by user uuid, so a user-scoped search
hits **one shard**. OpenSearch data streams refuse a routed write:

```
illegal_argument_exception: index request targeting data stream [...]
specifies a custom routing. target the backing indices directly or remove
the custom routing.
```

There is no flag to enable it, so on OpenSearch the router issues no routing key
and the template omits `allow_custom_routing`. Searches on the shared stream
then fan out across its shards.

Isolation is unaffected — that comes from the mandatory user filter, not from
routing. What changes is search cost on the shared stream, which scales with
`SHARED_SHARD_COUNT`. A user whose volume makes that expensive is exactly the
case dedicated streams exist for, and those never used routing on either
engine.

Two consequences worth knowing:

* **`flat_object` has narrower query semantics than `flattened`.** Term lookups
  on dotted paths work — which is what `labels.*` filters and the
  `clock_skew_suspect` marker need — but ranges and some aggregations do not.
  If you add a label query, verify it on OpenSearch specifically.
* **`text` costs more disk than `match_only_text`**, which drops norms and
  positions. Over six years of retention that is a real difference; budget for
  it when sizing EBS.

## User isolation

On Elasticsearch, a dedicated stream's `constant_keyword` makes the **engine
itself** refuse a document carrying another user's id. `SECURITY.md` counts
that as a layer of the isolation model, and OpenSearch has no dependable
equivalent — availability of `constant_keyword` varies across 2.x minors, and a
security control must not depend on a patch version.

So the guarantee moved into the code: **`AuditRepository.bulk_index` refuses to
write a document whose `user.uuid` disagrees with its route**, on both engines
and on the shared stream too — which neither engine ever guarded. A mismatch is
logged as `bulk_index_user_uuid_mismatch`, reported as a permanent failure, and
dead-lettered for a human rather than retried.

The engine check remains a second layer where the engine offers it. Net effect
by engine:

| Layer | Elasticsearch | OpenSearch |
|---|---|---|
| Mandatory query filter on reads | Yes | Yes |
| Repository write guard | Yes | Yes |
| Engine refuses a foreign user uuid | Yes, dedicated streams | No |

`tests/unit/test_opensearch_backend.py` covers the guard;
`tests/integration/test_end_to_end.py` asserts the extra Elastic layer is still
present rather than silently lost.

## Setting up a managed AWS domain

Two decisions first.

**VPC or public endpoint.** Production should be a VPC domain: this store holds
every user's audit trail and has no business having a public endpoint. A
public endpoint with an IP-restricted access policy is fine for a spike.

**Basic auth or SigV4.** Fine-grained access control with an internal master
user works with the settings the Elasticsearch path already uses
(`ES_USERNAME` / `ES_PASSWORD`), so it is the fastest route to a working
service. `OPENSEARCH_AWS_SIGV4=true` signs with the host's IAM credentials
instead and leaves no long-lived password on the audit host — the better
production posture.

AWS requires encryption at rest, node-to-node encryption and enforced HTTPS
before it will let you enable fine-grained access control. The console greys
FGAC out if the instance type cannot do encryption at rest; `t3.medium.search`
is the smallest worth using.

```bash
# Confirm the version string rather than guessing it.
aws opensearch list-versions --query 'Versions[?starts_with(@, `OpenSearch_2`)]'

aws opensearch create-domain \
  --domain-name everycred-audit-dev \
  --engine-version "OpenSearch_2.19" \
  --cluster-config InstanceType=t3.medium.search,InstanceCount=1 \
  --ebs-options EBSEnabled=true,VolumeType=gp3,VolumeSize=50 \
  --encryption-at-rest-options Enabled=true \
  --node-to-node-encryption-options Enabled=true \
  --domain-endpoint-options EnforceHTTPS=true,TLSSecurityPolicy=Policy-Min-TLS-1-2-2019-07 \
  --advanced-security-options \
      'Enabled=true,InternalUserDatabaseEnabled=true,MasterUserOptions={MasterUserName=audit_admin,MasterUserPassword=<generated>}' \
  --access-policies file://access-policy.json
```

For a public endpoint, the IP condition is doing real work — do not drop it:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "*" },
    "Action": "es:*",
    "Resource": "arn:aws:es:<region>:<account-id>:domain/everycred-audit-dev/*",
    "Condition": { "IpAddress": { "aws:SourceIp": ["<office-ip>/32", "<audit-host-ip>/32"] } }
  }]
}
```

`Principal: *` with `es:*` is only safe because FGAC authenticates every request
and the condition fences it. On a VPC domain, drop the condition — the VPC is
the boundary.

Production sizing: 3 data nodes across AZs plus 3 dedicated masters, EBS gp3.
Size storage from measured ingest — daily event volume × document size ×
(1 + replicas) × retention days, plus ~25% for merges. Measure a week of real
traffic before extrapolating six years.

## Configuration

```env
SEARCH_BACKEND=opensearch
# No port: the AWS endpoint is HTTPS on 443, unlike the :9200 default.
ES_HOSTS=https://search-everycred-audit-dev-xxxxxxxx.ap-south-1.es.amazonaws.com

# Either fine-grained access control...
ES_USERNAME=audit_admin
ES_PASSWORD=<master password>
# ...or SigV4, which needs no stored credential at all.
OPENSEARCH_AWS_SIGV4=false

# AWS serves a publicly-trusted certificate, so there is no CA to pin.
ES_CA_CERT_PATH=
ES_VERIFY_CERTS=true
```

The `ES_*` names are shared by both engines on purpose: hosts, timeouts and TLS
mean the same thing to either store, and only the credential differs. `AWS_REGION`
is reused from the archive settings for SigV4 signing.

Startup refuses a configuration with no credential and no SigV4, rather than
reaching an unauthenticated store.

## Running locally

```bash
docker compose up -d opensearch redis
# OpenSearch listens on 9202 so it can run beside Elasticsearch.
SEARCH_BACKEND=opensearch ES_HOSTS=http://localhost:9202 uv run audit-service bootstrap
SEARCH_BACKEND=opensearch ES_HOSTS=http://localhost:9202 uv run pytest -m integration
```

The local container runs with the security plugin disabled, which is also why it
serves plain HTTP. The service refuses an `http://` host when
`ENVIRONMENT=prod`.

CI runs the integration suite once per engine (`.github/workflows/ci.yml`,
`integration` job matrix). A change to the search layer is not verified until
both legs are green.

Current status of that matrix, run against Elasticsearch 9.2.0 and OpenSearch
2.19.6:

| Leg | Result |
|---|---|
| `elasticsearch` | 25 passed |
| `opensearch` | 23 passed, 2 skipped |

The two skips are the Elastic-only guarantees: `constant_keyword` refusing a
foreign user uuid, and the `allow_custom_routing` / `_routing` coupling. Both
skip explicitly rather than silently asserting nothing.

## Before production

- **VPC domain**, not public.
- **Confirm automated snapshots cover `audit-keyring-v1`.** Events survive in the
  S3 WORM archive; wrapped DEKs do not. Losing that index makes every encrypted
  PII field permanently unreadable — it is the one irreplaceable index.
- **Move to SigV4** so no long-lived password sits on the audit host, and keep the
  master user for break-glass only.
- **Create a limited FGAC role** for the service rather than running as the master
  user: it needs read/write on `audit-*` and the ISM and template APIs.
- **Set `INDEX_REPLICAS`** to match the node count. A single-node spike domain
  needs `0`, or every index sits yellow forever.
