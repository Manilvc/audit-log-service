"""Operational tooling that is not part of the request/response hot path.

Historical backfill from legacy Postgres NDJSON exports, and room for future
one-off migrations. Invoked via ``audit-service backfill``.
"""
