"""Response envelope.

Matches the main backend's `core/utils/standard_response.py` contract -
`{"status", "data", "message"}` - so existing frontend clients and service
callers parse audit responses with the code they already have. Diverging here
would force every consumer to special-case one service.
"""

from __future__ import annotations

from typing import Any, Literal

import orjson
from fastapi import Response

Status = Literal["success", "fail"]


class ORJSONResponse(Response):
    """JSON responses via orjson.

    Audit payloads are large and deeply nested; orjson serialises several times
    faster than the stdlib encoder and handles `datetime` and `UUID` natively,
    which removes a whole class of custom-encoder bugs.
    """

    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        """Serialise ``content`` with orjson (datetimes/UUIDs native)."""
        return orjson.dumps(content, option=orjson.OPT_NON_STR_KEYS)


def envelope(
    *,
    status: Status = "success",
    data: Any = None,
    message: str = "",
) -> dict[str, Any]:
    """Build the platform response envelope."""
    return {"status": status, "data": data, "message": message}


def success(
    data: Any = None,
    *,
    message: str = "",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> ORJSONResponse:
    """A successful response in the platform envelope."""
    return ORJSONResponse(
        content=envelope(status="success", data=data, message=message),
        status_code=status_code,
        headers=headers,
    )


def failure(
    message: str,
    *,
    data: Any = None,
    status_code: int = 400,
) -> ORJSONResponse:
    """A failed response in the platform envelope."""
    return ORJSONResponse(
        content=envelope(status="fail", data=data, message=message),
        status_code=status_code,
    )
