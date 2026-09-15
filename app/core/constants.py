"""Every literal the request surface depends on, in one place.

Header names, credential formats, index names and cache windows are contracts:
an emitter, an nginx rule, a dashboard and a test all have to agree on them. A
literal typed into a view or a service is a contract nobody can find, so they
live here and are imported by name.

Nothing in this module imports from the rest of the application, so it can be
read - or imported - from anywhere without a cycle.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Request headers
# ---------------------------------------------------------------------------
#: The credential. Either an env-configured service key (the admin plane) or an
#: issued key bound to one user (the ingest plane).
API_KEY_HEADER: Final[str] = "x-api-key"

#: User the call acts for. Authoritative only for an env-configured key; an
#: issued key carries its own user and this header may only agree with it.
USER_UUID_HEADER: Final[str] = "x-audit-user-uuid"

#: Issuer (sub-user) the call acts within. Batch default for `issuer_id`.
ISSUER_HEADER: Final[str] = "x-audit-issuer-id"

#: The person a service is acting for, recorded as `actor.on_behalf_of`.
ON_BEHALF_HEADER: Final[str] = "x-audit-on-behalf-of"

#: The calling service's own name, recorded for attribution. Unverified.
SERVICE_NAME_HEADER: Final[str] = "x-service-name"

#: Ceiling for an identity header, matching the domain field it is stored in.
MAX_IDENTITY_HEADER_LENGTH: Final[int] = 64

# ---------------------------------------------------------------------------
# Issued API keys
# ---------------------------------------------------------------------------
#: Human-readable marker at the front of every issued key, so a leaked string
#: in a log or a paste is recognisable as an EveryCRED audit credential and can
#: be matched by a secret scanner.
API_KEY_PREFIX: Final[str] = "evcaud"

#: Separates prefix, id and secret: `evcaud_<key_id>_<secret>`. The id is the
#: document id in the store, so verification is one point lookup rather than a
#: scan over every key.
#:
#: The underscore is also a character `secrets.token_urlsafe` emits, so the
#: split is bounded (see `API_KEY_PART_COUNT`) and the id is hex - the secret is
#: the last field and may contain anything, the two before it may not.
API_KEY_SEPARATOR: Final[str] = "_"

#: Parts a well-formed key splits into: prefix, id, secret. The split is bounded
#: to this many, so an underscore inside the secret stays part of the secret
#: instead of turning a valid key into an unparseable one.
API_KEY_PART_COUNT: Final[int] = 3

#: Bytes of entropy behind the id and the secret. The id is rendered as hex so
#: it can never contain the separator; 16 bytes makes a collision implausible.
#: The secret is 32 bytes url-safe, which puts brute force out of reach and is
#: why a fast digest is the right hash here (see `api_key_service`).
API_KEY_ID_BYTES: Final[int] = 16
API_KEY_SECRET_BYTES: Final[int] = 32

#: Characters of the secret kept in clear on the record, so an operator can tell
#: two keys apart in a list without the key itself being recoverable.
API_KEY_HINT_LENGTH: Final[int] = 6

#: Scopes an issued key receives unless the caller narrows them. Write only:
#: an emitter needs to store events and nothing else, and a key that can also
#: read is a key that can exfiltrate the trail it was issued to fill.
DEFAULT_ISSUED_KEY_SCOPES: Final[tuple[str, ...]] = ("audit:write",)

#: Scopes an issued key may never hold, whatever the request asks for. These
#: reach across users or destroy data, so they stay with the env-configured
#: admin credential that is rotated by deploy rather than by API.
FORBIDDEN_ISSUED_KEY_SCOPES: Final[frozenset[str]] = frozenset(
    {"audit:erase", "audit:admin", "audit:cross_user"}
)

#: Lifecycle states a key record can be in. Revoked keys are kept rather than
#: deleted: "this key was revoked on the 3rd" is evidence, "no such key" is not.
API_KEY_STATUS_ACTIVE: Final[str] = "active"
API_KEY_STATUS_REVOKED: Final[str] = "revoked"

#: Where issued keys live. A plain index, not a data stream: a key is mutable
#: state (revocation, last-used) rather than an append-only event.
API_KEY_INDEX_SUFFIX: Final[str] = "api-keys-v1"

#: How long a verified key stays in the process cache. The whole point is to
#: keep the ingest path off the network, so this is also the worst-case delay
#: before a revocation takes effect on an already-warm replica. Overridable as
#: `API_KEY_CACHE_TTL_SECONDS`.
DEFAULT_API_KEY_CACHE_TTL_SECONDS: Final[int] = 60

#: How long an issued key lives unless the caller asks for less. A year is long
#: enough not to be a nuisance and short enough that a forgotten key expires.
DEFAULT_API_KEY_EXPIRY_DAYS: Final[int] = 365

#: Cap on cached keys, so a burst of distinct credentials cannot grow the
#: process heap without bound.
API_KEY_CACHE_MAX_ENTRIES: Final[int] = 4096

#: Page size ceiling when listing keys for a user.
API_KEY_LIST_MAX_SIZE: Final[int] = 200

# ---------------------------------------------------------------------------
# Domains an issued key is bound to
# ---------------------------------------------------------------------------
#: The emitting system a key is issued to - `hrms.acme.example`, say. Recorded
#: on the key and stamped onto every event it writes, so an entry in the trail
#: names the system that produced it and a compromised key's blast radius is
#: readable off the log.
MAX_DOMAIN_LENGTH: Final[int] = 253

#: Hostname shape: dot-separated labels of letters, digits and hyphens, each
#: starting and ending alphanumeric. No scheme, no path, no port - this is an
#: identity, not a URL anything calls back.
#:
#: Written without lookarounds on purpose: pydantic compiles patterns with the
#: Rust regex engine, which has none, and `(?!-)` fails at import time rather
#: than at validation time.
_DOMAIN_LABEL: Final[str] = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DOMAIN_PATTERN: Final[str] = rf"^{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*$"

#: Free-text note on a key, for the operator who has to recognise it later.
MAX_KEY_LABEL_LENGTH: Final[int] = 128

# ---------------------------------------------------------------------------
# Console listing
# ---------------------------------------------------------------------------
#: The unfiltered chip above the audit log table. A named constant because it
#: is both the query-parameter default and the value echoed back in the
#: response, and those two must not drift apart.
FILTER_PRESET_ALL: Final[str] = "all"

#: Ceiling on an inbound pagination cursor. A cursor this service issues is a
#: base64 of two short sort values - well under 200 characters - so anything
#: past this is either a mistake or an attempt to make the decoder do work.
MAX_CURSOR_LENGTH: Final[int] = 512

#: Default rows per page in the console table. Matches DEFAULT_PAGE_SIZE, but
#: is a separate constant because the listing is a UI contract: changing what a
#: table shows should not require touching a search-tuning setting.
DEFAULT_LISTING_PAGE_SIZE: Final[int] = 50

#: How much of an event message may become a row title before it is trimmed.
#: A row is one line; a 8 KB message pushed through a table cell is a layout
#: problem, and the full text is in the event itself.
MAX_ROW_TITLE_LENGTH: Final[int] = 160
