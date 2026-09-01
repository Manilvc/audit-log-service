"""Elasticsearch integration for audit documents and the PII keyring.

``client`` / ``bootstrap`` / ``mappings``
    Hardened client, idempotent cluster provisioning, ILM + index templates.
``routing`` / ``query`` / ``repository``
    Hybrid tenant → data-stream resolution, tenant-scoped DSL builder, CRUD.
``keyring``
    Wrapped per-subject DEKs used by crypto-shredding.
"""
