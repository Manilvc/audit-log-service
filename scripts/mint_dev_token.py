"""Mint a platform JWT for local API testing.

The audit service does not issue tokens - it validates the ones the main
EveryCRED backend already signs, using the shared `JWT_SECRET_KEY`. That is fine
in a running platform and useless on a laptop, where there is no backend to log
into. This script signs a token with the same secret and the same claim shape,
so Swagger's `PlatformJWT` box and any HTTP client have something to send.

    uv run python scripts/mint_dev_token.py
    uv run python scripts/mint_dev_token.py --tenant <uuid> --scopes audit:read,audit:export

Refuses to run against a production configuration: a script that mints
credentials from a secret on disk is a development convenience, and pointing it
at prod would be issuing a real platform token from a laptop.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import get_settings
from app.domain.enums import Scope

# Long enough to work through a testing session without re-minting, short enough
# that a token left in a shell history stops working the same day.
_DEFAULT_TTL_MINUTES = 480


def main() -> int:
    parser = argparse.ArgumentParser(description="Mint a development platform JWT.")
    parser.add_argument(
        "--tenant",
        default=None,
        help="Tenant id the token acts for. A random UUID is generated when omitted.",
    )
    parser.add_argument(
        "--scopes",
        default=",".join(s.value for s in Scope),
        help="Comma-separated scopes. Defaults to every scope.",
    )
    parser.add_argument(
        "--subject", default="dev.user@example.com", help="Email for the sub claim."
    )
    parser.add_argument(
        "--ttl", type=int, default=_DEFAULT_TTL_MINUTES, help="Lifetime in minutes."
    )
    args = parser.parse_args()

    settings = get_settings()
    if settings.is_production:
        print("refusing to mint a token against a production configuration", file=sys.stderr)
        return 2

    requested = [s.strip() for s in args.scopes.split(",") if s.strip()]
    valid = {s.value for s in Scope}
    unknown = [s for s in requested if s not in valid]
    if unknown:
        print(f"unknown scope(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"valid scopes: {', '.join(sorted(valid))}", file=sys.stderr)
        return 2

    tenant_id = args.tenant or str(uuid.uuid4())
    now = datetime.now(UTC)

    claims = {
        # The main backend stores a JSON document here rather than a bare id, and
        # `_parse_identity` reads `uuid` and `email` out of it. Matching that
        # shape means a token from this script and one from the platform are
        # interchangeable.
        "sub": json.dumps({"email": args.subject, "uuid": str(uuid.uuid4())}),
        "tenant_id": tenant_id,
        # Claim name is `audit_scopes`, not `scope` or `scopes`. An empty or
        # absent list is not an error: the principal is then restricted to its
        # own history, which is a much narrower token than it looks.
        "audit_scopes": requested,
        "sid": f"sess_{uuid.uuid4().hex[:12]}",
        "aud": settings.JWT_AUDIENCE,
        "iss": settings.JWT_ISSUER,
        "iat": now,
        # `exp` is required by the validator: a token without it would otherwise
        # validate forever.
        "exp": now + timedelta(minutes=args.ttl),
    }

    token = jwt.encode(
        claims,
        settings.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )

    # The token goes to stdout alone, so it can be piped or captured; everything
    # a human needs goes to stderr.
    print(token)
    print(
        f"\ntenant_id : {tenant_id}"
        f"\nscopes    : {', '.join(requested) or '(none - self-history only)'}"
        f"\nexpires   : {claims['exp'].isoformat(timespec='seconds')}"
        f"\naudience  : {settings.JWT_AUDIENCE}   issuer: {settings.JWT_ISSUER}"
        "\n\nPaste the token above into Swagger's PlatformJWT box (no 'Bearer ' prefix -"
        "\nSwagger adds it), or send it as: Authorization: Bearer <token>",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
