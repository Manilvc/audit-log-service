"""API router assembly.

One place that knows every route the service exposes, so an endpoint cannot be
added without appearing here - which keeps the security review surface knowable.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import compliance, events, ops

v1_router = APIRouter()
v1_router.include_router(events.router)
v1_router.include_router(compliance.router)
v1_router.include_router(ops.admin_router)

# Health and metrics sit outside the versioned prefix: an orchestrator's probe
# configuration should not have to change when the API version does.
ops_router = APIRouter()
ops_router.include_router(ops.router)
