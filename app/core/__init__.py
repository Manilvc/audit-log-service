"""Cross-cutting infrastructure shared by the API and the worker.

Settings, structured logging, Prometheus metrics, the HTTP middleware stack,
platform response envelope, exception handlers, tamper-evidence primitives,
and the ``security`` subpackage (JWT/API-key auth + PII crypto).
"""
