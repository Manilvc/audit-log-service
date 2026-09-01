"""Elasticsearch index topology: ILM policy, component and index templates.

Everything here is declarative and idempotent - `bootstrap.py` applies it on
startup, so a fresh cluster converges to the right shape with no manual curl.

Why the mapping looks like this
-------------------------------
``dynamic: strict``
    An unmapped field is a hard indexing error, not a silently unsearchable
    one. Combined with ``extra="forbid"`` on the ingest schema, a field nobody
    declared cannot reach the cluster. Rejected documents land in the dead-letter
    queue and raise an alert, so the failure is loud instead of being discovered
    during an incident. Free-form emitter data has a home already: ``labels``.

``flattened`` for ``labels`` / ``change.before`` / ``change.after``
    These hold arbitrary business fields. Mapped as objects they would be a
    mapping explosion - one emitter logging a per-record diff could add
    thousands of fields to a shared index and eventually break the cluster.
    ``flattened`` indexes the whole subtree as one field: still queryable by
    exact key/value, with a fixed mapping cost.

``constant_keyword`` for ``tenant.id`` on dedicated streams
    Doubles as a storage-layer isolation guarantee. A backing index adopts the
    tenant id of its first document, and any later document with a different
    tenant id is *rejected by Elasticsearch*. Cross-tenant contamination in a
    dedicated stream becomes impossible rather than merely unlikely. It also
    makes the tenant filter free to evaluate.

``index.sort`` on ``@timestamp`` descending
    The overwhelmingly common query is "most recent events first". A
    descending index sort lets Lucene terminate early instead of scoring a
    whole segment.

Custom routing by tenant (shared stream only)
    ``allow_custom_routing`` lets a tenant's documents be pinned to one shard,
    so a tenant-scoped search fans out to one shard instead of all of them. The
    hot-shard risk this introduces is exactly what promoting a heavy tenant to
    a dedicated stream solves.

    The flag has a side effect worth knowing: Elasticsearch marks ``_routing``
    as **required** on every backing index of a stream that allows custom
    routing. So it is set on the shared template, where every write supplies a
    routing key, and left off the dedicated template, where none is supplied.

``best_compression``
    Audit data is written once and read rarely. Trading a little decompression
    CPU for roughly 20-30% less disk is clearly right over a six-year horizon.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Reusable mapping fragments
# ---------------------------------------------------------------------------
_KEYWORD: dict[str, Any] = {"type": "keyword"}

# `ignore_above` caps what gets indexed while _source keeps the full value:
# protects against a pathological term without losing evidence.
_KEYWORD_1024: dict[str, Any] = {"type": "keyword", "ignore_above": 1024}

# Identifiers that are only ever *filtered* on - never sorted or aggregated -
# can drop doc_values for a meaningful disk saving on the widest fields.
_KEYWORD_FILTER_ONLY: dict[str, Any] = {
    "type": "keyword",
    "ignore_above": 256,
    "doc_values": False,
}

# `event.id` looks like a filter-only identifier but is NOT: it is the
# search_after sort tiebreaker (see search.query.SORT_TIEBREAKER), and sorting
# reads doc_values. Dropping them here makes every paginated search fail with
# "Can't load fielddata on [event.id]". Keep doc_values on.
_KEYWORD_SORTABLE_ID: dict[str, Any] = {
    "type": "keyword",
    "ignore_above": 256,
}


def _event_mapping(tenant_id_field: dict[str, Any]) -> dict[str, Any]:
    """Build the audit document mapping.

    Args:
        tenant_id_field: `keyword` for the shared stream, `constant_keyword`
            for a dedicated one.
    """
    return {
        "dynamic": "strict",
        "_source": {"enabled": True},
        "properties": {
            "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
            "event": {
                "dynamic": "strict",
                "properties": {
                    # Sortable: the search_after tiebreaker.
                    "id": _KEYWORD_SORTABLE_ID,
                    "action": _KEYWORD,
                    "category": _KEYWORD,
                    "type": _KEYWORD,
                    "outcome": _KEYWORD,
                    "severity": _KEYWORD,
                    "ingested": {"type": "date"},
                    "reason": _KEYWORD_1024,
                },
            },
            "tenant": {
                "dynamic": "strict",
                "properties": {
                    "id": tenant_id_field,
                    "name": _KEYWORD_1024,
                    "issuer_id": _KEYWORD,
                },
            },
            "actor": {
                "dynamic": "strict",
                "properties": {
                    "type": _KEYWORD,
                    "id": _KEYWORD,
                    "numeric_id": {"type": "long"},
                    # email / name / phone are absent by design: they are PII
                    # and live encrypted in `pii_ct`. Mapping them would invite
                    # a future emitter to write plaintext into an indexed field.
                    "user_type": _KEYWORD,
                    "session_id": _KEYWORD,
                    "on_behalf_of": _KEYWORD,
                    "service": _KEYWORD,
                    # Optional deterministic lookup hashes (disabled by default).
                    "email_bidx": _KEYWORD_FILTER_ONLY,
                    "phone_bidx": _KEYWORD_FILTER_ONLY,
                },
            },
            "target": {
                "dynamic": "strict",
                "properties": {
                    "type": _KEYWORD,
                    "id": _KEYWORD,
                    "numeric_id": {"type": "long"},
                    "ids": _KEYWORD_FILTER_ONLY,
                    "count": {"type": "long"},
                },
            },
            "source": {
                "dynamic": "strict",
                "properties": {
                    # Full address is encrypted; only the truncated network
                    # prefix is indexed, which is the GDPR minimisation pattern.
                    "ip_prefix": _KEYWORD,
                    "country_code": _KEYWORD,
                    "city": _KEYWORD_1024,
                    "device_type": _KEYWORD,
                },
            },
            "http": {
                "dynamic": "strict",
                "properties": {
                    "method": _KEYWORD,
                    "path": _KEYWORD_1024,
                    "status_code": {"type": "short"},
                    "duration_ms": {"type": "float"},
                    "request_id": _KEYWORD_FILTER_ONLY,
                    "trace_id": _KEYWORD,
                },
            },
            "change": {
                "dynamic": "strict",
                "properties": {
                    "fields": _KEYWORD,
                    "before": {"type": "flattened"},
                    "after": {"type": "flattened"},
                },
            },
            "service": {
                "dynamic": "strict",
                "properties": {"name": _KEYWORD, "version": _KEYWORD},
            },
            # `match_only_text` is the log-optimised text type: no norms and no
            # term frequencies, so ~10% smaller than `text` with the same
            # match/phrase behaviour. Only populated when PII encryption is off.
            "message": {"type": "match_only_text"},
            "labels": {"type": "flattened"},
            "integrity": {
                "dynamic": "strict",
                "properties": {
                    "seq": {"type": "long"},
                    "prev_hash": _KEYWORD_FILTER_ONLY,
                    "hash": _KEYWORD_FILTER_ONLY,
                    "algo": _KEYWORD,
                    "chain_id": _KEYWORD,
                },
            },
            "pii": {
                "dynamic": "strict",
                "properties": {
                    "encrypted": {"type": "boolean"},
                    "key_id": _KEYWORD_FILTER_ONLY,
                    "kek_version": {"type": "short"},
                    "fields": _KEYWORD_FILTER_ONLY,
                    "shredded": {"type": "boolean"},
                    "shredded_at": {"type": "date"},
                },
            },
            # Ciphertext: retrievable from _source, never indexed. `enabled:
            # false` means no inverted index, no doc_values, and no way to
            # search or aggregate encrypted blobs.
            "pii_ct": {"type": "object", "enabled": False},
        },
    }


def ilm_policy(
    *,
    retention_days: int,
    rollover_max_primary_shard_size: str,
    rollover_max_age: str,
) -> dict[str, Any]:
    """Hot -> warm -> cold -> delete lifecycle.

    The delete phase is the *maximum* retention permitted, not the mechanism for
    honouring erasure requests - those are served by crypto-shredding, which
    leaves the record in place. Deleting a record early would break the hash
    chain and destroy audit evidence.

    HIPAA 164.316(b)(2)(i) sets the six-year floor that `retention_days`
    defaults to.
    """
    return {
        "policy": {
            "_meta": {
                "description": (
                    "EveryCRED audit retention. Delete phase is the regulatory "
                    "maximum; erasure requests are served by crypto-shredding."
                ),
                "managed_by": "everycred-audit-service",
            },
            "phases": {
                "hot": {
                    "actions": {
                        "rollover": {
                            "max_primary_shard_size": rollover_max_primary_shard_size,
                            "max_age": rollover_max_age,
                        },
                        # Cap segment count on the hot tier so search stays fast
                        # while the index is still receiving writes.
                        "set_priority": {"priority": 100},
                    }
                },
                "warm": {
                    "min_age": "30d",
                    "actions": {
                        # Read-only + a single segment: best possible search
                        # latency and disk footprint for immutable data.
                        "forcemerge": {"max_num_segments": 1},
                        "readonly": {},
                        "set_priority": {"priority": 50},
                    },
                },
                "cold": {
                    "min_age": "180d",
                    "actions": {
                        # Replicas drop to 0 in cold: durability comes from the
                        # S3 WORM archive and cluster snapshots, so paying for a
                        # second copy of five-year-old data is waste.
                        "allocate": {"number_of_replicas": 0},
                        "set_priority": {"priority": 0},
                    },
                },
                "delete": {
                    "min_age": f"{retention_days}d",
                    "actions": {"delete": {"delete_searchable_snapshot": False}},
                },
            },
        }
    }


def _base_settings(
    *,
    shards: int,
    replicas: int,
    ilm_policy_name: str,
) -> dict[str, Any]:
    return {
        "index": {
            "number_of_shards": shards,
            "number_of_replicas": replicas,
            # Allows a later `shrink` down to any divisor without a reindex.
            "number_of_routing_shards": 30,
            "lifecycle": {"name": ilm_policy_name},
            "codec": "best_compression",
            # Newest-first is the dominant access pattern; a descending index
            # sort lets Lucene stop early instead of scanning whole segments.
            "sort": {"field": "@timestamp", "order": "desc"},
            # Strict mapping means the field count is bounded by design; a low
            # ceiling turns an accidental explosion into an immediate error.
            "mapping": {
                "total_fields": {"limit": 200},
                "ignore_malformed": False,
            },
            # Audit search must never silently return partial results, so a
            # 1s refresh is an acceptable trade for much cheaper indexing than
            # the 200ms default under bulk load.
            "refresh_interval": "1s",
            "query": {"default_field": ["event.action", "message"]},
        }
    }


def shared_index_template(
    *,
    name_pattern: str,
    shards: int,
    replicas: int,
    ilm_policy_name: str,
    priority: int = 200,
) -> dict[str, Any]:
    """Template for the multi-tenant shared data stream.

    `tenant.id` is a plain `keyword`: the isolation guarantee here is the
    mandatory filter injected by `search.query`, backed by the tests in
    `tests/unit/test_tenant_isolation.py`.
    """
    return {
        "index_patterns": [name_pattern],
        # Enabling custom routing also makes `_routing` REQUIRED on every
        # backing index - Elasticsearch sets `_routing: {required: true}`
        # automatically. Every write to the shared stream must therefore supply
        # a routing value, which `TenantRouter.resolve` guarantees by returning
        # the tenant id as `routing_key` for shared tenants.
        "data_stream": {"allow_custom_routing": True},
        "priority": priority,
        "template": {
            "settings": _base_settings(
                shards=shards, replicas=replicas, ilm_policy_name=ilm_policy_name
            ),
            "mappings": _event_mapping(_KEYWORD),
        },
        "_meta": {"managed_by": "everycred-audit-service", "isolation": "shared"},
    }


def dedicated_index_template(
    *,
    name_pattern: str,
    shards: int,
    replicas: int,
    ilm_policy_name: str,
    priority: int = 300,
) -> dict[str, Any]:
    """Template for per-tenant dedicated data streams.

    Higher priority than the shared template so `audit-t-<uuid>-*` wins over
    any broader pattern. `tenant.id` becomes `constant_keyword`, which makes
    Elasticsearch itself reject a document carrying the wrong tenant id.
    """
    return {
        "index_patterns": [name_pattern],
        # Custom routing is deliberately NOT enabled here. Enabling it would
        # make `_routing` required on the backing indices, and a dedicated
        # stream has no routing key to supply - the stream is already scoped to
        # one tenant, so pinning to a single shard would only remove headroom.
        # Setting the flag anyway would reject every write with
        # `routing_missing_exception`.
        "data_stream": {},
        "priority": priority,
        "template": {
            "settings": _base_settings(
                shards=shards, replicas=replicas, ilm_policy_name=ilm_policy_name
            ),
            "mappings": _event_mapping({"type": "constant_keyword"}),
        },
        "_meta": {"managed_by": "everycred-audit-service", "isolation": "dedicated"},
    }


# ---------------------------------------------------------------------------
# Keyring index - deliberately NOT a data stream
# ---------------------------------------------------------------------------
def keyring_index_settings(*, replicas: int) -> dict[str, Any]:
    """Mapping for the wrapped-DEK store.

    A normal index rather than a data stream, because erasure must *delete* from
    it - that deletion is the whole crypto-shredding mechanism. It is the one
    mutable store in the service.

    Operationally this index is the single point of failure for readability of
    all PII: lose it and every encrypted field is gone forever. It must be in
    the snapshot policy, and it holds only wrapped keys, so the KEK still gates
    any use of a stolen copy.
    """
    return {
        "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": replicas,
                "refresh_interval": "1s",
                # Every read is a by-id GET, so no sorting or scoring is needed.
                "codec": "best_compression",
            }
        },
        "mappings": {
            "dynamic": "strict",
            "properties": {
                # base64 of the wrapped DEK. Not indexed: it is only ever
                # fetched by document id.
                "wrapped": {"type": "keyword", "index": False, "doc_values": False},
                "kek_version": {"type": "short"},
                "created_at": {"type": "date"},
                # Tombstone fields, set when a DSR erasure destroys the key.
                # Keeping the tombstone lets the reader distinguish "erased on
                # request" from "never existed", which auditors ask about.
                "shredded": {"type": "boolean"},
                "shredded_at": {"type": "date"},
                "shred_reason": {"type": "keyword", "ignore_above": 512},
                "shred_request_id": {"type": "keyword"},
            },
        },
    }
