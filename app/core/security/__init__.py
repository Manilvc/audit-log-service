"""Authentication, authorisation, and field-level PII cryptography.

``auth``
    Platform JWT + service ``x-api-key`` → ``Principal`` and audit scopes.
``crypto``
    Per-subject AES-GCM encryption and crypto-shredding (key destruction).
"""
