"""HTTP API layer.

Routers, FastAPI dependency injection, and the composition root that wires
long-lived collaborators (ES, Redis, cipher, services) once at startup.
"""
