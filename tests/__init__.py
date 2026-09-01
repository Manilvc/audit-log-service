"""Test suite for the EveryCRED Audit Log Service.

``unit``
    Pure / faked tests — no Docker required (``pytest -m "not integration"``).
``integration``
    End-to-end against the local compose stack (ES, Redis, MinIO).
"""
