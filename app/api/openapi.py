"""OpenAPI schema enrichment.

FastAPI infers a correct but bare schema: it knows the request and response
models, and nothing about how a developer is meant to *use* the API. Three gaps
matter enough to close here, because each one is invisible in the generated
document and expensive to discover by trial and error:

1. **Authentication is undocumented.** The credential and the user header
   both arrive through plain ``Header`` dependencies, so the generated schema
   lists them as unexplained optional headers with no security scheme attached.
   A reader cannot tell that ``x-api-key`` is the credential, that
   ``x-audit-user-uuid`` is mandatory alongside it on every user-scoped
   route, or that the two do different jobs.
2. **Tags carry no prose.** ReDoc renders a tag as a navigation heading, so an
   untagged description is a section with a title and no introduction.
3. **No examples.** A schema tells you a field is a ``Keyword``; an example tells
   you it is ``credential.issue``.

Everything here is presentation. It is applied to the generated document, never
to the routes, so the schema can be enriched without the auth path or the
handler signatures acquiring documentation concerns.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from app.core.config import Environment, Settings
from app.core.constants import (
    API_KEY_HEADER,
    ISSUER_HEADER,
    ON_BEHALF_HEADER,
    USER_UUID_HEADER,
)

# ---------------------------------------------------------------------------
# Security schemes
# ---------------------------------------------------------------------------
# One credential, one user header, and only the first of them is a security
# scheme. `x-audit-user-uuid` is not a credential - it grants nothing and is
# checked only for shape - so describing it as one would tell a reader that
# naming a user is what authorises the call. It is documented as an ordinary
# required header instead, in `_HEADER_DESCRIPTIONS` below.
SECURITY_SCHEMES: dict[str, dict[str, Any]] = {
    "ServiceApiKey": {
        "type": "apiKey",
        "in": "header",
        "name": API_KEY_HEADER,
        "description": (
            "**Machine-to-machine credential.** Used by the emitting services "
            "(everycred-backend, consent, contributor, verifier, signer) to write "
            "events and by trusted internal readers.\n\n"
            "The key is matched in constant time against the `SERVICE_API_KEYS` "
            "allow-list, which is comma-separated so a key can be rotated with an "
            "overlap window: add the new key, redeploy every emitter, then drop the "
            "old one.\n\n"
            "A valid key carries every audit scope - including `audit:erase` and "
            "`audit:cross_user` - because it is the only credential this service "
            "accepts. Treat it accordingly.\n\n"
            "A service principal is not bound to a user, so it **must** name the "
            f"user it is acting for via the `{USER_UUID_HEADER}` header."
        ),
    },
}

# The service key is the only credential the authenticator accepts.
SECURITY_REQUIREMENT: list[dict[str, list[str]]] = [
    {"ServiceApiKey": []},
]

# The credential-bearing header is described by the scheme above. Left in the
# parameter list as well, it appears a second time as an untyped optional
# header, which reads as though it were something else you might also send.
_CREDENTIAL_HEADERS = frozenset({API_KEY_HEADER.lower()})

# These are ordinary headers rather than credentials, so they stay - but the
# generated schema gives them no description, and each is easy to get wrong.
_HEADER_DESCRIPTIONS: dict[str, str] = {
    USER_UUID_HEADER.lower(): (
        "User the call acts for. **Required** on every user-scoped route: "
        "the API key is not bound to a user, so this header is the only thing "
        "that scopes the request. It may be omitted only on search and aggregate "
        "with `cross_user=true`.\n\n"
        "Send the user's UUID as your own system knows it. It is checked for "
        "shape (`[A-Za-z0-9._-]`, 1-63 chars, alphanumeric first) and otherwise "
        "trusted: **you** are expected to have resolved and authorised the user "
        "before calling, because this service holds no user registry to check "
        "against. A well-formed id for a user that does not exist is accepted, "
        "and its events then belong to a user nobody can read.\n\n"
        "On ingest, an event whose body `user_uuid` disagrees with this header is "
        "rejected rather than silently resolved."
    ),
    ON_BEHALF_HEADER.lower(): (
        "The end user a service is acting for - the service user id. Stamped "
        "onto `actor.on_behalf_of` on every event the call ingests, and onto the "
        "audit-of-the-audit record for every read.\n\n"
        "Set it whenever a backend performs work triggered by a person, so the "
        "trail attributes the action to the human and not to the service "
        "account. An event that fills in `actor.on_behalf_of` itself keeps its "
        "own value."
    ),
    ISSUER_HEADER.lower(): (
        "Issuer (sub-user) the call acts within, recorded as `user.issuer_id` "
        "and filterable on search and aggregate.\n\n"
        "A batch default, not an override: an event carrying its own `issuer_id` "
        "keeps it, so one call can span several issuers inside a user. Unlike "
        "the user header this is descriptive rather than a boundary - reads are "
        "not scoped by it unless you ask - so at most 64 characters is the only "
        "constraint."
    ),
}


# ---------------------------------------------------------------------------
# Tag metadata
# ---------------------------------------------------------------------------
TAGS_METADATA: list[dict[str, Any]] = [
    {
        "name": "Audit Events",
        "description": (
            "Write and read the audit trail.\n\n"
            "**Writes return `202 Accepted`, not `201`.** The request path does no "
            "crypto, no Elasticsearch and no S3: it validates, resolves the user "
            "and enqueues. The event is searchable about a second later. Reporting "
            "`201` would imply it is queryable immediately, which a caller might "
            "then build a read-after-write assumption on.\n\n"
            "**Partial success is normal.** One malformed event does not reject the "
            "batch - check `rejected` and `errors`, which report the index of each "
            "failed event within the batch you sent.\n\n"
            "**Reads are searches, never document GETs.** A mandatory user filter "
            "is injected in the query layer, so guessing another user's event id "
            "returns `404` rather than the record. Every search is itself recorded "
            "as an audit event, as HIPAA 164.312(b) and SOC 2 CC7.2 require."
        ),
    },
    {
        "name": "Compliance",
        "description": (
            "Prove the trail is intact, and honour an erasure request without "
            "breaking that proof.\n\n"
            "**Integrity verification** walks a user's hash chain and reports the "
            "first break, distinguishing modification from deletion, reordering and "
            "insertion. Chain heads are notarised into WORM storage, so even a "
            "wholesale rewrite of Elasticsearch is detectable.\n\n"
            "**Erasure is crypto-shredding, not deletion.** The data subject's "
            "encryption key is destroyed; the record stays exactly where it is, with "
            "its hash and its position in the chain unchanged. That is what lets "
            "GDPR Art. 17 and DPDP s.12 coexist with the immutability SOC 2, "
            "ISO 27001 and HIPAA require. It is irreversible."
        ),
    },
    {
        "name": "Operations",
        "description": (
            "Health, metrics and user topology.\n\n"
            "`/health/live` deliberately checks nothing external: a liveness probe "
            "that fails during an Elasticsearch upgrade would make the orchestrator "
            "restart every replica and turn a degraded read path into an outage. "
            "`/health/ready` does check dependencies, because a replica that cannot "
            "reach its dependencies should be taken out of the load balancer.\n\n"
            "Promoting a user to a dedicated data stream is non-destructive: reads "
            "still cover the shared stream, so history from before the promotion "
            "stays visible."
        ),
    },
]

# Deliberately no `x-tagGroups`. It groups the ReDoc sidebar, but it is also a
# filter: once any group exists, ReDoc hides every section not assigned to one -
# including the Authentication section it generates from `securitySchemes`.
# Losing the sidebar entry for authentication to gain headings over three tags is
# a bad trade, and grouping only starts to earn its keep past roughly a dozen.


# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
# Realistic rather than minimal. A developer copies the example, so it should
# show the fields worth sending - notably `event_id`, whose absence is the
# single most common cause of duplicate events after a retry.
_INGEST_EXAMPLE: dict[str, Any] = {
    "events": [
        {
            "action": "credential.issue",
            "timestamp": "2026-08-31T09:14:22.310Z",
            "category": "credential",
            "type": "creation",
            "outcome": "success",
            "message": "Issued a Class XII marksheet credential",
            "actor": {
                "type": "user",
                "id": "8f14e45f-ceea-4f3a-9a1b-1c4a2b3d5e6f",
                "email": "registrar@example.edu",
                "session_id": "sess_01JQ8ZC2M7",
            },
            "target": {
                "type": "credential",
                "id": "urn:uuid:2c9a5f10-8d4b-4f2e-b7c1-5a9e3f0d1234",
                "name": "Class XII Marksheet",
            },
            "source": {"ip": "203.0.113.24", "country_code": "IN", "device_type": "desktop"},
            "http": {
                "method": "POST",
                "path": "/api/v1/credentials/issue",
                "status_code": 201,
                "duration_ms": 184,
                "request_id": "req_7f3c1b9a",
            },
            "service_name": "everycred-backend",
            "service_version": "3.4.1",
            "labels": {"batch_id": "batch_2026_08_31_a"},
            "event_id": "evt_01JQ8ZC2M7X4K9",
        }
    ]
}

_INGEST_RESPONSE_EXAMPLE: dict[str, Any] = {
    "status": "success",
    "data": {"accepted": 1, "rejected": 0, "errors": []},
    "message": "1 event(s) accepted.",
}

_SEARCH_EXAMPLE: dict[str, Any] = {
    "start": "2026-08-01T00:00:00Z",
    "end": "2026-08-31T23:59:59Z",
    "categories": ["credential"],
    "outcomes": ["failure"],
    "actor_ids": ["8f14e45f-ceea-4f3a-9a1b-1c4a2b3d5e6f"],
    "size": 50,
    "with_total": True,
}

_AGGREGATE_EXAMPLE: dict[str, Any] = {
    "start": "2026-08-01T00:00:00Z",
    "end": "2026-08-31T23:59:59Z",
    "group_by": "action",
    "interval": "1d",
    "buckets": 30,
}

# No `user_uuid` in either compliance example: both models are `extra: forbid`
# and the user comes from the credential or the `x-audit-user-uuid` header.
# Sending it in the body is a 422, so an example that included it would send a
# developer straight into a validation error on their first call.
_VERIFY_EXAMPLE: dict[str, Any] = {
    "start_seq": 0,
    "max_events": 10000,
}

_ERASURE_EXAMPLE: dict[str, Any] = {
    "subject_id": "holder_9f2c4a71",
    "reason": "GDPR Art. 17 erasure request, ticket DSR-2026-0417",
    "request_reference": "DSR-2026-0417",
    # `Literal[True]`, and required. Crypto-shredding cannot be undone, so the
    # caller states the intent explicitly rather than reaching it by default.
    "confirm": True,
}

#: Operations whose route takes `UserUuidDep`, so the user header is
#: mandatory. FastAPI cannot infer this: the dependency declares a `None`
#: default on purpose, so a missing header produces an explanatory 400 instead
#: of a bare 422 listing a header name. Curated here like the examples below,
#: and `tests/unit/test_identity_headers.py` fails if it drifts from the routes.
_USER_UUID_REQUIRED_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("/v1/audit/events", "post"),
        ("/v1/audit/events/{event_id}", "get"),
        ("/v1/audit/events/timeline/{target_id}", "get"),
        ("/v1/audit/events/export", "post"),
        ("/v1/audit/compliance/integrity/verify", "post"),
        ("/v1/audit/compliance/erasure", "post"),
    }
)

#: Keyed by ``(path, method)``, applied to the request body after generation.
_REQUEST_EXAMPLES: dict[tuple[str, str], dict[str, Any]] = {
    ("/v1/audit/events", "post"): _INGEST_EXAMPLE,
    ("/v1/audit/events/search", "post"): _SEARCH_EXAMPLE,
    ("/v1/audit/events/aggregate", "post"): _AGGREGATE_EXAMPLE,
    ("/v1/audit/compliance/integrity/verify", "post"): _VERIFY_EXAMPLE,
    ("/v1/audit/compliance/erasure", "post"): _ERASURE_EXAMPLE,
}

_RESPONSE_EXAMPLES: dict[tuple[str, str, str], dict[str, Any]] = {
    ("/v1/audit/events", "post", "202"): _INGEST_RESPONSE_EXAMPLE,
}


# ---------------------------------------------------------------------------
# Shared error responses
# ---------------------------------------------------------------------------
# Every authenticated operation can return these, and FastAPI documents none of
# them because they are raised by middleware and dependencies rather than
# declared per route. A reader who does not know 429 is possible will not write
# a retry.
def _error_example(message: str) -> dict[str, Any]:
    """Build the platform failure envelope used by every error response."""
    return {"status": "fail", "data": None, "message": message}


_COMMON_ERRORS: dict[str, dict[str, Any]] = {
    "400": {
        "description": (
            "No `x-audit-user-uuid` header on a route that acts for one user, a "
            "user uuid that is not shaped like one, or a filter the query builder "
            "refused. The message says which."
        ),
        "content": {
            "application/json": {
                "example": _error_example(
                    "the x-audit-user-uuid header is required: it names the user "
                    "this call acts for, and the API key is not bound to a user"
                )
            }
        },
    },
    "401": {
        "description": (
            "No `x-api-key` header, or a key that is not on the allow-list. The "
            "reason is deliberately not distinguished in the response."
        ),
        "content": {"application/json": {"example": _error_example("no credentials supplied")}},
    },
    "403": {
        "description": (
            "Authenticated, but the principal lacks the scope for this operation - "
            "or asked for another user's data without `audit:cross_user`."
        ),
        "content": {
            "application/json": {"example": _error_example("scope audit:export is required")}
        },
    },
    "429": {
        "description": (
            "Rate limit exceeded for this principal. Reads are capped low "
            "(`READ_RATE_LIMIT_PER_MINUTE`) because reads are the sensitive surface; "
            "ingest is capped high, because throttling ingest means dropping audit "
            "evidence. Retry after the window."
        ),
        "content": {"application/json": {"example": _error_example("rate limit exceeded")}},
    },
}


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------
def _servers(settings: Settings) -> list[dict[str, str]]:
    """Server list for the docs.

    A relative URL is always correct - it resolves against whatever host is
    serving the document - so it is the only entry outside local development,
    where an absolute one saves a reader from guessing the port.
    """
    if settings.ENVIRONMENT is Environment.LOCAL:
        return [
            {
                "url": f"http://localhost:{settings.SERVER_PORT}",
                "description": "Local development",
            }
        ]
    return [{"url": "/", "description": "This deployment"}]


def _decorate_operation(path: str, method: str, operation: dict[str, Any]) -> None:
    """Apply auth, header prose, examples and shared errors to one operation."""
    # Drop the credential headers now that a security scheme describes them, and
    # annotate the two that remain.
    params = []
    for param in operation.get("parameters", []):
        name = str(param.get("name", "")).lower()
        if param.get("in") == "header" and name in _CREDENTIAL_HEADERS:
            continue
        if param.get("in") == "header" and name in _HEADER_DESCRIPTIONS:
            param["description"] = _HEADER_DESCRIPTIONS[name]
            # `str | None` generates an anyOf whose auto-titles render as
            # "X-Audit-User-Id (string) or X-Audit-User-Id (null)". It is a
            # string; saying so plainly is both accurate and readable, and
            # `required` below carries the optionality.
            param["schema"] = {"type": "string"}
            if name == USER_UUID_HEADER.lower():
                param["required"] = (path, method) in _USER_UUID_REQUIRED_OPERATIONS
        params.append(param)
    if params:
        operation["parameters"] = params
    else:
        operation.pop("parameters", None)

    example = _REQUEST_EXAMPLES.get((path, method))
    if example is not None:
        body = operation.get("requestBody", {}).get("content", {}).get("application/json")
        if body is not None:
            body["example"] = example

    responses = operation.setdefault("responses", {})
    for code, spec in _COMMON_ERRORS.items():
        responses.setdefault(code, spec)

    for (ex_path, ex_method, ex_code), payload in _RESPONSE_EXAMPLES.items():
        if ex_path == path and ex_method == method and ex_code in responses:
            content = (
                responses[ex_code].setdefault("content", {}).setdefault("application/json", {})
            )
            content["example"] = payload


def build_openapi(app: FastAPI, settings: Settings) -> dict[str, Any]:
    """Generate the enriched schema, caching it on the app.

    FastAPI caches by assigning to ``app.openapi_schema``; the same convention is
    kept here so a repeated ``/openapi.json`` request does not regenerate a
    document that cannot change without a restart.
    """
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=TAGS_METADATA,
        servers=_servers(settings),
    )

    schema["info"]["contact"] = {
        "name": "EveryCRED Platform Engineering",
        "url": "https://everycred.com",
    }
    schema["info"]["license"] = {"name": "Proprietary - EveryCRED"}
    schema["info"]["x-logo"] = {"altText": "EveryCRED", "backgroundColor": "#0B1220"}

    components = schema.setdefault("components", {})
    components.setdefault("securitySchemes", {}).update(SECURITY_SCHEMES)

    # Applied at the document level so every operation inherits it. The health
    # and metrics probes are unauthenticated, but they are excluded from the
    # schema entirely (`include_in_schema=False`), so nothing here mislabels them.
    schema["security"] = SECURITY_REQUIREMENT

    for path, methods in schema.get("paths", {}).items():
        for method, operation in methods.items():
            if isinstance(operation, dict):
                _decorate_operation(path, method, operation)

    app.openapi_schema = schema
    return schema
