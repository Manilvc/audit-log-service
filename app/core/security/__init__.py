"""Authentication, authorisation, and field-level PII cryptography.

``auth``
    Service ``x-api-key`` → ``Principal`` and audit scopes.
``crypto``
    Per-subject AES-GCM encryption and crypto-shredding (key destruction).
"""
