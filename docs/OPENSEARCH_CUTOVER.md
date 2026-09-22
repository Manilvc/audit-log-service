# OpenSearch cutover

Moving a running deployment from the self-hosted Elasticsearch node to a managed
AWS OpenSearch domain: console setup, configuration, verification, and the
failure modes this cutover actually produces.

For the engine's behavioural differences and local development against
OpenSearch see [OPENSEARCH_DEPLOYMENT.md](./OPENSEARCH_DEPLOYMENT.md). For the
service itself see [DEPLOYMENT.md](./DEPLOYMENT.md).

---

## Before you start

The service supports both engines behind one interface. Hosts, timeouts and TLS
mean the same thing to either store; **only the credential mechanism differs**.
Which adapter `search.backends.build_backend` constructs is decided by a single
setting, `SEARCH_BACKEND`, and getting that one line wrong is the cause of most
of [Failure modes](#failure-modes) below.

### Version

The client is pinned `opensearch-py>=2.8,<3`, so the server must be
**OpenSearch 2.x**. The AWS console defaults to the latest 3.x and you have to
change it: 3.x is untested against this client, and the pin exists because
`opensearch-py` 3.x pulls `grpcio` and `protobuf` for a transport this service
does not use.

### The one irreversible decision

**VPC or public access.** Network mode is fixed at creation; everything else on
the form — including the access policy — can be edited afterwards. A VPC domain
is reachable only from inside that VPC, so establish where the audit host lives
before choosing:

```bash
# on the audit host
curl -s --max-time 2 http://169.254.169.254/latest/meta-data/instance-id \
  && echo " <- EC2" || echo "NOT EC2"
```

| Result | Choose | Secured by |
|---|---|---|
| `NOT EC2` | **Public access** | Fine-grained access control + an IP-conditioned policy |
| `<- EC2` | **VPC access** | The VPC, plus a security group allowing 443 from the host |

A VPC domain created for a host outside the VPC is unreachable, and the only fix
is to recreate the domain.

---

## 1. Create the domain

Console → **Amazon OpenSearch Service → Domains → Create domain**. Anything not
listed keeps its default.

| Panel | Setting | Value |
|---|---|---|
| Name | Domain name | `everycred-audit-dev` |
| Creation method | Method | **Standard create** — *Easy create* hides encryption and FGAC |
| Use cases | Use case | **Custom** |
| Templates | Template | **Dev/test** |
| Deployment | Deployment option | **Domain without standby** |
| Deployment | Availability Zones | **1-AZ** |
| Engine | Version | **OpenSearch 2.19** — not the 3.x default |
| Data nodes | Instance family | General purpose |
| Data nodes | Instance type | `m7g.medium.search` |
| Data nodes | Node count | **1** |
| Storage | EBS | gp3 · 50 GiB · 3000 IOPS · 125 MiB/s |
| Warm / cold | Tiered storage | **off** |
| Network | Network | Per the check above |
| Network | IP address type | **IPv4 only** |
| Access control | Fine-grained access control | **Enabled** → *Create master user* |
| Access control | Master username | `audit_admin` |
| Access policy | Domain access policy | *Only use fine-grained access control*, or *Configure domain level access policy* with an IP condition |
| Encryption | HTTPS, node-to-node, at rest | **all three** — required by FGAC, and both encryption settings are permanent |
| Auto-Tune | Auto-Tune | Turn on |
| Advanced cluster settings | Multi-index APIs | **leave checked** — bulk ingest depends on it |
| — | SAML, JWT, Cognito, IAM Identity Center, Amazon Q, S3 Vectors | all off |

`m7g.medium.search` is the floor worth using: smaller types cannot do encryption
at rest, and the console greys fine-grained access control out without it.

### Why warm and cold storage stay off

The ISM policy this service applies has states named `warm` and `cold`, but they
are **not** AWS storage tiers. They run on the same hot nodes and perform
`force_merge`, `read_only` and `replica_count: 0` — see
`search/backends/opensearch.py`. Provisioning UltraWarm would bill for capacity
nothing ever migrates into, and real tiering would need a `warm_migration`
action added to those states as well as the nodes.

### Two console traps

**"Domain with standby" re-selects itself.** Changing the engine version
re-renders the deployment panel and silently restores it. That option mandates
3-AZ zone awareness, which contradicts a one-node cluster and surfaces as
*"You must configure zone awareness settings if you turn on zone awareness"* at
the bottom of the form — nowhere near the control that caused it. Re-check the
deployment option after every engine change.

Fixing it also removes the forced three dedicated master nodes, which on a
one-node dev domain cost several times the data node they supervise.

**Dual-stack requires IPv6 on every subnet.** Selecting it against subnets
without an IPv6 CIDR fails validation with `IPv6CIDRBlockNotFoundForSubnet`
*after* provisioning starts. Use IPv4 only; public access removes the question
entirely.

### Checkpoint

```bash
ES="https://search-everycred-audit-dev-XXXXXXXX.ap-south-1.es.amazonaws.com"
curl -sS -u "audit_admin:$OS_PASS" -w "\nHTTP %{http_code}\n" \
  "$ES/_cluster/health?pretty"
```

`HTTP 200` and `"status" : "green"`. Do not continue until both hold.

---

## 2. Point the service at the domain

> ### Duplicate keys win
>
> The `.env` parser takes the **last** occurrence of a key. A file that has
> accumulated edits commonly carries `ES_CA_CERT_PATH` twice — appending a new
> value works, but editing an earlier line does not. Find duplicates before
> touching anything.

```bash
cd /var/www/audit-log-service
cp .env .env.elasticsearch-backup

grep -nE '^(SEARCH_BACKEND|ES_|OPENSEARCH_|INDEX_REPLICAS)=' .env \
  | awk -F: '{print $2}' | cut -d= -f1 | sort | uniq -d
```

Anything printed is duplicated. Delete the earlier copies, then set:

```env
SEARCH_BACKEND=opensearch

# AWS endpoint: no :9200, HTTPS on 443
ES_HOSTS=https://search-everycred-audit-dev-XXXXXXXX.ap-south-1.es.amazonaws.com

ES_USERNAME=audit_admin
ES_PASSWORD='<master password>'
OPENSEARCH_AWS_SIGV4=false

# AWS serves a publicly-trusted certificate — nothing to pin. This MUST be
# empty: the previous value points at the local Elasticsearch CA.
ES_CA_CERT_PATH=
ES_VERIFY_CERTS=true

# One data node cannot host a replica of its own primary.
INDEX_REPLICAS=0
```

| Key | Was | Becomes |
|---|---|---|
| `SEARCH_BACKEND` | *absent* → `elasticsearch` | `opensearch` |
| `ES_HOSTS` | `https://localhost:9200` | AWS endpoint, no port |
| `ES_USERNAME` | `elastic` | `audit_admin` |
| `ES_PASSWORD` | local ES password | OpenSearch master password |
| `ES_CA_CERT_PATH` | `/etc/ssl/certs/es-ca.crt` | **empty** |
| `ES_API_KEY` | unset | stays unset — Elasticsearch-only, rejected here |
| `INDEX_REPLICAS` | *absent* → `1` | `0` |

Single-quote any password containing `,` `>` `=` or `#`.

`OPENSEARCH_AWS_SIGV4=true` is the alternative to a stored password, signing
with the host's IAM role. It needs an instance role, so it is only available on
an EC2 or container host.

### The archive target moves too

This is the step that is easy to miss, because nothing about it fails at
startup. Moving the search backend to AWS does **not** move the WORM archive,
and a host cut over from local Elasticsearch is usually also running local
MinIO:

```env
# Leftovers from the local stack - both wrong once the host is on AWS.
S3_ENDPOINT_URL=http://localhost:9000
ARCHIVE_BUCKET=everycred-audit-archive-local
```

Left as-is, ingest keeps working and reads keep working, so the cutover looks
clean. Only the worker notices, once per batch:

```
archive_seal_failed  error='archive write failed for audit/events/...ndjson.gz:
An error occurred (404) when calling the PutObject operation: Not Found'
```

A bare `404` rather than `NoSuchBucket` means nothing S3-shaped answered at all
- the error body carried no `<Code>`, so botocore fell back to the HTTP status.
That is the signature of an endpoint override pointing at a MinIO that is no
longer there.

The consequence is worse than the log suggests. The seal failure leaves the
batch unacknowledged, the redelivery finds the events already in OpenSearch,
and the duplicate path resyncs the chain and acknowledges. The events stay
queryable, but **no immutable segment covers them** and the orphaned
reservation leaves a numbering gap. Nothing is lost; the tamper-evidence
guarantee simply does not apply to that window, and re-sealing after the fact
needs the events read back out of the ledger.

So change both keys in the same edit as the search keys:

```env
# Comment out, do NOT blank: an empty value is not None, and boto rejects it
# with `ValueError: Invalid endpoint:` at client construction.
#S3_ENDPOINT_URL=
ARCHIVE_BUCKET=everycred-audit-archive-dev
```

Create the bucket in the same account and region as the domain, with Object
Lock enabled *at creation* - it cannot be added later. Commands in
[DEPLOYMENT.md](./DEPLOYMENT.md#s3-worm-bucket).

On an EC2 host, leave `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` unset and
let the instance role supply credentials - the archive falls through to boto's
default chain. The role needs `s3:PutObject` **and** `s3:PutObjectRetention`;
without the second the 404 merely becomes an `AccessDenied`.

### Checkpoint

Config validation refuses to start with neither credential nor SigV4, so a
mistake here is a clean crash rather than a runtime 503. Confirm what the
application *resolves*, not what the file appears to say — this is the step that
catches a surviving duplicate:

```bash
.venv/bin/python -c "
from app.core.config import get_settings
s = get_settings()
print('backend :', s.SEARCH_BACKEND)
print('hosts   :', s.ES_HOSTS)
print('user    :', s.ES_USERNAME)
print('pwd len :', len(s.ES_PASSWORD.get_secret_value()))
print('ca path :', repr(s.ES_CA_CERT_PATH))
print('replicas:', s.INDEX_REPLICAS)
print('archive :', s.ARCHIVE_BUCKET, '@', s.S3_ENDPOINT_URL or 'aws')
"
```

Expect `SearchEngine.OPENSEARCH`, `audit_admin`, `ca path : ''`, and a `pwd len`
matching the real password. `archive` must print `@ aws` and a real bucket name
- `@ http://localhost:9000` means the archive was left behind on the local
stack.

---

## 3. Bootstrap and restart

> ### Use `restart`, never `start`
>
> `audit-bootstrap` is `Type=oneshot` with `RemainAfterExit=yes`. Once it has
> succeeded systemd considers the unit *active*, and `systemctl start` on an
> active unit is a **silent no-op** — it reports success and does nothing.

```bash
sudo systemctl stop audit-workers audit

sudo systemctl restart audit-bootstrap
journalctl -u audit-bootstrap --since "-2min" --no-pager \
  | grep -E "engine|data_streams_created|error"

sudo systemctl start audit
sudo systemctl start audit-workers
```

Workers stop before the API and start after it, for the reason given in
[DEPLOYMENT.md](./DEPLOYMENT.md): an older build's worker running against the
same Redis keyspace chains from a stale head and produces `prev_mismatch` breaks
indistinguishable from tampering.

### Checkpoint

```
search_backend_selected  engine=opensearch  pinned_user_uuid_type=keyword
cluster_bootstrap_complete  data_streams_created=['audit-shared']
```

`pinned_user_uuid_type=keyword` rather than `constant_keyword` is the OpenSearch
adapter identifying itself.

> ### Reading `data_streams_created: []`
>
> `bootstrap_cluster` re-applies index templates unconditionally but creates data
> streams **only if absent**. An empty list means "the stream already existed and
> was left untouched" — which on an existing cluster is exactly how a stale
> mapping survives a template change. On a new domain it means bootstrap did not
> really run.

---

## 4. Mint the ingest key

The new cluster's key index is empty, so every previously issued `evcaud_…`
credential is gone. Mint a replacement with a key from `SERVICE_API_KEYS`: the
route requires `audit:admin`, which an issued key can never hold.

```bash
SERVICE_KEY="$(grep -E '^SERVICE_API_KEYS=' .env | cut -d= -f2- | cut -d, -f1)"

curl -sS -X POST "https://api-evrc.viitorcloud.in/audit/v1/audit/admin/api-keys" \
  -H "x-api-key: $SERVICE_KEY" \
  -H "content-type: application/json" \
  -w "\nHTTP %{http_code}\n" \
  -d '{"domain":"api-evrc.viitor.cloud",
       "label":"Everycred Backend",
       "scopes":["audit:write","audit:read"],
       "all_users":true,
       "expires_in_days":365}'
```

- **No `x-audit-user-uuid` header.** Sending one alongside `all_users` is
  refused, because it implies a binding that is not being created.
- `all_users: true` stores no user on the record, so the header names the user
  per request and one credential serves a backend acting for everyone.
- It stays weaker than the env credential: `audit:erase`, `audit:admin` and
  `audit:cross_user` are refused however they are requested, and unlike an env
  key it has a record — listed, attributed to a domain, and revocable without a
  redeploy.

### Checkpoint

`HTTP 201`, with `"user_uuid": null` in the response confirming the key is
unbound. `api_key` is returned **once** and is not stored; copy it into the main
backend's `AUDIT_SERVICE_API_KEY` and restart the backend.

---

## 5. Prove a write reaches disk

The HTTP response cannot tell you this. Ingest queues through Redis and returns
before Elasticsearch is involved, so a rejected write surfaces in the worker
rather than in the caller's status code.

```bash
# terminal 1
journalctl -u audit-workers -f \
  | grep -iE "strict_dynamic|dead_letter|permanent|indexed"
```

```bash
# terminal 2
NOW="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"

curl -sS -X POST "https://api-evrc.viitorcloud.in/audit/v1/audit/events" \
  -H "x-api-key: $NEW_EVCAUD_KEY" \
  -H "x-audit-user-uuid: $USER_UUID" \
  -H "content-type: application/json" \
  -w "\nHTTP %{http_code}\n" \
  -d "{\"action\":\"user.login\",\"category\":\"authentication\",\"timestamp\":\"$NOW\"}"

sleep 5
curl -sS -u "audit_admin:$OS_PASS" "$ES/audit-shared/_count?pretty"
```

**Use a current timestamp.** Searches default to a window ending *now*, so a
future-dated `timestamp` is stored successfully and stays invisible to every
search until the clock catches up — which reads exactly like a lost event.

### Inspecting stored data

Dashboards is at `$ES/_dashboards/`. **Dev Tools** is the fastest surface:

```
GET audit-shared/_count
GET audit-shared/_search
{ "size": 20, "sort": [{ "@timestamp": "desc" }] }
```

For **Discover**, create an index pattern `audit-shared*` — the asterisk matters,
it has to match the `.ds-audit-shared-*` backing indices — with `@timestamp` as
the time field, and widen the default 15-minute range.

PII fields (`actor.email`, `actor.name`, `source.ip`, `message`) are encrypted at
write and show as ciphertext in Dashboards. Only the audit API's read path
decrypts them. That is correct behaviour, not corruption.

---

## Failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `406 Content-Type header [application/vnd.elasticsearch+x-ndjson; compatible-with=8] is not supported` | The Elasticsearch client is pointed at an OpenSearch domain — `SEARCH_BACKEND` missing or not `opensearch` | Set it; confirm the log says `engine=opensearch` |
| `401 Your request: '/_ilm/policy/audit-retention' is not allowed` | Same root cause. `_ilm` is Elasticsearch-only; OpenSearch uses ISM | As above |
| Any traceback inside `search/backends/elastic.py` | Definitive proof the Elasticsearch adapter was constructed | Check the *effective* config, not the file |
| `IPv6CIDRBlockNotFoundForSubnet` | Dual-stack selected, subnets carry no IPv6 CIDR | IP address type → IPv4 only |
| *"must configure zone awareness settings"* | "Domain with standby" re-selected itself; it mandates 3-AZ | Re-select *Domain without standby*, then 1-AZ |
| `data_streams_created: []` on a new domain | Bootstrap did not run, or the stream already existed | `restart`, not `start` |
| `systemctl start audit-bootstrap` reports success, nothing changes | `Type=oneshot` + `RemainAfterExit=yes` | Use `restart` |
| `Wildcard expressions or all indices are not allowed` | `action.destructive_requires_name` blocks `DELETE /audit-*` | Delete by explicit name |
| `strict_dynamic_mapping_exception` in the worker | A backing index predates the current template. Classified permanent, so dead-lettered rather than retried | Recreate the stream, clear the DLQs |
| Cluster stuck **yellow** | One data node cannot host a replica of its own primary | `INDEX_REPLICAS=0`, or add nodes |
| A `curl` prints nothing at all | `$ES` or auth unset; `-s` swallows "URL malformed" | Always `-sS -w "\nHTTP %{http_code}\n"` |
| `archive_seal_failed` with `An error occurred (404) ... PutObject ... Not Found` | `S3_ENDPOINT_URL` still points at the local MinIO, which is gone. A bare `404` instead of `NoSuchBucket` means no S3 answered | Comment out the override, set a real Object Lock bucket; see *The archive target moves too* |
| A config edit has no effect | Duplicate key later in `.env`, or the unit's `WorkingDirectory` points at another checkout | `systemctl show audit -p WorkingDirectory`; de-duplicate |

### Clearing dead-lettered events

```bash
for i in $(seq 0 7); do
  printf "p%s dlq=%s\n" "$i" "$(redis-cli XLEN audit:stream:$i:dlq)"
done

redis-cli --scan --pattern 'audit:stream:*:dlq' | xargs -r redis-cli del
```

Anything non-zero is evidence lost to the misconfiguration, not a transient
backlog — a permanent rejection is never retried.

---

## What changes on OpenSearch

| Behaviour | Elasticsearch | OpenSearch |
|---|---|---|
| Shard routing | User pinned to one shard via a routing key | Data streams reject routed writes; the key is omitted and searches fan out |
| `pinned_user_uuid` mapping | `constant_keyword` — the *engine* rejects a foreign document | `keyword` — no engine-level guard |
| Lifecycle policy | ILM phases | ISM states and transitions |
| Serverless collections | n/a | **Not supported** — templates, ISM and point-in-time are restricted |

Cross-user isolation is unaffected: it comes from the mandatory `user.uuid`
filter applied to every read, not from routing, so fanning out costs performance
and nothing else.

The **write** guard is what changes. Without `constant_keyword` the engine will
accept a document bound for the wrong stream, leaving the application-level check
in `search/repository.py` as the only thing enforcing it. That guard matters more
here, not less.

---

## Rollback

```bash
cd /var/www/audit-log-service
cp .env.elasticsearch-backup .env
sudo systemctl restart audit audit-workers
```

This only helps if the self-hosted Elasticsearch is healthy. Check
`systemctl is-active elasticsearch` — a wiped `/var/lib/elasticsearch` commonly
fails to start on directory ownership, which
`chown -R elasticsearch:elasticsearch /var/lib/elasticsearch` resolves. The real
reason is always in `/var/log/elasticsearch/*.log` rather than in the systemd
status output.

---

## Before this domain becomes permanent

The configuration above is dev-grade: one data node, zero replicas, no dedicated
masters. A single node failure loses everything since the last hourly snapshot.

Production wants three data nodes across three AZs, `INDEX_REPLICAS=1`, dedicated
masters, a VPC endpoint, and storage sized from a measured week of real ingest —
daily volume × document size × (1 + replicas) × retention days, plus ~25% for
merge headroom. Retention is 2190 days with rollover at 50 GB per primary shard
or 30 days, so do not extrapolate six years from a guess.

Durability for aged data comes from the S3 WORM archive and cluster snapshots,
which is why the `cold` ISM state drops replicas to zero rather than paying twice
for the same guarantee.
