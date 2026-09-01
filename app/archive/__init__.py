"""Immutable WORM archive on S3 (or MinIO locally) with Object Lock.

Seals event segments and notarises chain-head checkpoints so a rewritten
Elasticsearch tail contradicts an object nobody can change.
"""
