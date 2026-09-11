"""Application services — use-cases called by the HTTP layer and the CLI.

``ingest_service``
    Validate, resolve user, enqueue (never does crypto/ES/S3 on the request path).
``query_service``
    User-scoped search/get/aggregate/export with PII decryption and audit-of-audit.
``compliance_service``
    Hash-chain integrity verification and data-subject crypto-shredding.
"""
