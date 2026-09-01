"""EveryCRED Audit Log Service.

Tamper-evident, multi-tenant audit logging for the EveryCRED DCS platform.
This package is the Python application root; the supported entrypoint is the
``audit-service`` CLI (see ``app.cli``).

Public layout
-------------
``api``
    HTTP surface: routers, FastAPI dependencies, composition root.
``archive``
    S3 Object Lock WORM segments and chain checkpoints.
``core``
    Cross-cutting infrastructure: config, auth, crypto, integrity, logging,
    metrics, middleware, responses, exceptions.
``domain``
    Canonical taxonomy (ECS actions/categories) and the internal event model.
``queue``
    Redis Streams ingest buffer, hash-chain allocator, and the worker process.
``schemas``
    Wire (request/response) Pydantic models, separate from the domain model.
``search``
    Elasticsearch client, mappings, routing, query builder, repository, keyring.
``services``
    Application services: ingest, query, compliance (integrity + erasure).
``tools``
    Operational one-offs such as historical backfill from legacy Postgres exports.
"""

__version__ = "1.0.0"
