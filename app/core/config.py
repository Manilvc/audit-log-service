"""Typed application settings.

Every value is sourced from the environment (12-factor). Secrets have **no
defaults** - the service refuses to start rather than fall back to a guessable
value, which is a deliberate compliance control (SOC 2 CC6.1).

Load order: process env > .env file > field default.
"""

from __future__ import annotations

import json
import ssl
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

#: `NoDecode` switches off pydantic-settings' automatic JSON decoding for a
#: list-typed field. Without it the settings *source* tries `json.loads` on the
#: raw env string and fails before any validator runs, so a plain
#: `A=x,y,z` value would be a startup crash rather than a parsed list.
#: With it, `_split_csv` below owns the parsing and accepts both CSV and JSON.
CsvList = Annotated[list[str], NoDecode]
CsvSecretList = Annotated[list[SecretStr], NoDecode]


class Environment(StrEnum):
    """Deployment tier. Drives production hardening checks at boot."""

    LOCAL = "local"
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class Settings(BaseSettings):
    """Typed environment configuration for the API and the worker.

    Secrets have no defaults: missing values fail startup rather than falling
    back to something guessable (SOC 2 CC6.1). List fields accept CSV or JSON.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---------------------------------------------------------------- service
    ENVIRONMENT: Environment = Environment.LOCAL
    SERVICE_NAME: str = "everycred-audit-service"
    API_V1_PREFIX: str = "/v1"
    # Binding to all interfaces is correct inside a container: the network
    # boundary is the pod / security group, not the process. The nginx config in
    # deploy/ is what restricts external exposure.
    SERVER_HOST: str = "0.0.0.0"  # noqa: S104  # nosec B104
    SERVER_PORT: int = 8020
    DEBUG: bool = False

    # Expose /docs only outside production. The audit API schema describes the
    # shape of the whole platform's activity, which is reconnaissance value.
    ENABLE_DOCS: bool = False

    # ------------------------------------------------------------------- CORS
    # Deliberately empty by default. The audit reader UI origin must be listed
    # explicitly; the main backend's broad allow_origins=["*"] is NOT copied
    # here, because these endpoints return cross-user personal data.
    CORS_ALLOW_ORIGINS: CsvList = Field(default_factory=list)

    # ------------------------------------------------------------------- auth
    # Must match the main backend's signing key (config/signing_cookies.py ->
    # SIGNIN_SECRET_KEY) so platform-issued access tokens validate here too.
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512", "RS256"] = "HS256"
    JWT_AUDIENCE: str
    JWT_ISSUER: str = "Your-Issuer"
    JWT_LEEWAY_SECONDS: int = 30

    # Service-to-service ingest credentials. A list, so keys can be rotated
    # with an overlap window (old + new both valid during the cutover).
    SERVICE_API_KEYS: CsvSecretList = Field(default_factory=list)

    # ---------------------------------------------------------- elasticsearch
    ES_HOSTS: CsvList = Field(default_factory=lambda: ["https://localhost:9200"])
    # API-key auth is preferred over basic auth: scoped, revocable, and no
    # password material on the wire. Set ES_API_KEY or ES_USERNAME+ES_PASSWORD.
    ES_API_KEY: SecretStr | None = None
    ES_USERNAME: str | None = None
    ES_PASSWORD: SecretStr | None = None
    ES_CA_CERT_PATH: str | None = None
    ES_VERIFY_CERTS: bool = True
    ES_REQUEST_TIMEOUT: float = 20.0
    ES_MAX_RETRIES: int = 3

    # --------------------------------------------------------- index topology
    INDEX_PREFIX: str = "audit"
    # Shared data stream used by every tenant without a dedicated stream.
    SHARED_DATA_STREAM: str = "audit-shared"
    # Tenants promoted to their own data stream (high volume or contractual
    # isolation), as a comma-separated list of tenant UUIDs.
    DEDICATED_TENANTS: CsvList = Field(default_factory=list)
    ILM_POLICY_NAME: str = "audit-retention"
    # HIPAA 164.316(b)(2)(i) requires 6 years retention of audit records.
    RETENTION_DAYS: int = 2190
    ROLLOVER_MAX_PRIMARY_SHARD_SIZE: str = "50gb"
    ROLLOVER_MAX_AGE: str = "30d"
    SHARED_SHARD_COUNT: int = 3
    DEDICATED_SHARD_COUNT: int = 1
    INDEX_REPLICAS: int = 1

    # ------------------------------------------------------- query guardrails
    # Deep pagination uses PIT + search_after, never from/size, so this caps a
    # single page rather than a whole result set.
    MAX_PAGE_SIZE: int = 200
    DEFAULT_PAGE_SIZE: int = 50
    # track_total_hits defaults to false for speed; when a caller does ask for
    # a count, cap the accuracy instead of scanning every matching document.
    TOTAL_HITS_CAP: int = 10_000
    # Refuse unbounded time ranges - an audit search with no window is a
    # full-retention scan across six years of data.
    MAX_QUERY_WINDOW_DAYS: int = 400
    SEARCH_TIMEOUT: str = "20s"

    # ------------------------------------------------------------ redis queue
    REDIS_URL: SecretStr = SecretStr("redis://localhost:6379/0")
    STREAM_KEY_PREFIX: str = "audit:stream"
    STREAM_CONSUMER_GROUP: str = "audit-writers"
    # Hash-chain ordering is per-partition, so a tenant is always pinned to
    # exactly one partition (see queue.partitioning).
    STREAM_PARTITIONS: int = 8
    STREAM_MAX_LEN: int = 1_000_000
    WORKER_BATCH_SIZE: int = 500
    WORKER_BLOCK_MS: int = 2000
    WORKER_MAX_DELIVERY_ATTEMPTS: int = 5

    # -------------------------------------------------------- S3 WORM archive
    ARCHIVE_ENABLED: bool = True
    ARCHIVE_BUCKET: str = ""
    ARCHIVE_PREFIX: str = "audit"
    AWS_REGION: str = "ap-south-1"
    # Endpoint override lets local development point at MinIO.
    S3_ENDPOINT_URL: str | None = None
    AWS_ACCESS_KEY_ID: SecretStr | None = None
    AWS_SECRET_ACCESS_KEY: SecretStr | None = None
    # COMPLIANCE mode cannot be shortened or removed by any user, including the
    # account root. That property is what makes the archive genuine WORM
    # evidence rather than merely a backup.
    OBJECT_LOCK_MODE: Literal["COMPLIANCE", "GOVERNANCE"] = "COMPLIANCE"
    OBJECT_LOCK_RETAIN_DAYS: int = 2190
    ARCHIVE_SEGMENT_MAX_EVENTS: int = 5_000
    ARCHIVE_SEGMENT_MAX_SECONDS: int = 300
    ARCHIVE_KMS_KEY_ID: str | None = None

    # ------------------------------------------------ crypto-shredding / PII
    # Master key-encryption key: 32 bytes, base64url-encoded. Wraps every
    # per-subject data key. Rotate by adding a KEK version, never in place.
    PII_MASTER_KEK: SecretStr
    PII_KEK_VERSION: int = 1
    # Set false only for a deployment with no personal data in scope.
    PII_ENCRYPTION_ENABLED: bool = True

    # ------------------------------------------------------------ rate limits
    RATE_LIMIT_ENABLED: bool = True
    # Reads are the sensitive surface: low ceiling, per principal.
    READ_RATE_LIMIT_PER_MINUTE: int = 120
    # Ingest is machine traffic from trusted services: high ceiling.
    INGEST_RATE_LIMIT_PER_MINUTE: int = 20_000
    MAX_REQUEST_BODY_BYTES: int = 5 * 1024 * 1024  # 5 MiB
    MAX_INGEST_BATCH_SIZE: int = 500

    # ------------------------------------------------------------ clock skew
    # Tolerance between an emitter's claimed `timestamp` and this service's
    # receipt time before the event is marked as clock-suspect.
    #
    # An audit trail is only reconstructable if the clocks agree, and an emitter
    # with a wrong clock corrupts the timeline *silently* - the record looks
    # exactly like a correct one. Flagging costs nothing and turns an invisible
    # failure into a queryable one.
    #
    # Deliberately generous: 5 minutes absorbs ordinary NTP drift and the delay
    # between an action and its emission, so a flag means a real problem rather
    # than noise. This does NOT replace running NTP on every emitting host - it
    # only detects when someone has not.
    MAX_CLOCK_SKEW_SECONDS: int = 300

    # ------------------------------------------------------------- validators
    @field_validator(
        "CORS_ALLOW_ORIGINS",
        "ES_HOSTS",
        "DEDICATED_TENANTS",
        "SERVICE_API_KEYS",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Accept "a,b,c" as well as a JSON list for list-typed settings.

        `NoDecode` means this validator owns the parsing outright - pydantic
        will not attempt JSON itself - so a bracketed value has to be decoded
        here rather than passed through.
        """
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                try:
                    return json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"value looks like JSON but does not parse: {exc}") from exc
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _enforce_production_hardening(self) -> Settings:
        """Fail fast on configurations that would be unsafe in production.

        Checking at boot converts a silent security regression into a loud
        deploy failure.
        """
        if self.ENVIRONMENT is Environment.PROD:
            problems: list[str] = []
            if self.DEBUG:
                problems.append("DEBUG must be false in prod")
            if self.ENABLE_DOCS:
                problems.append("ENABLE_DOCS must be false in prod")
            if not self.ES_VERIFY_CERTS:
                problems.append("ES_VERIFY_CERTS must be true in prod")
            if any(host.startswith("http://") for host in self.ES_HOSTS):
                problems.append("ES_HOSTS must use https in prod")
            if "*" in self.CORS_ALLOW_ORIGINS:
                problems.append("CORS_ALLOW_ORIGINS must not contain '*' in prod")
            if self.ARCHIVE_ENABLED and not self.ARCHIVE_BUCKET:
                problems.append("ARCHIVE_BUCKET is required when ARCHIVE_ENABLED")
            if self.ARCHIVE_ENABLED and self.OBJECT_LOCK_MODE != "COMPLIANCE":
                problems.append("OBJECT_LOCK_MODE must be COMPLIANCE in prod")
            if not self.SERVICE_API_KEYS:
                problems.append("SERVICE_API_KEYS is required in prod")
            if problems:
                raise ValueError("Unsafe production configuration: " + "; ".join(problems))

        # RFC 7518 s.3.2: an HMAC key shorter than the hash output weakens the
        # signature. PyJWT only warns; for a service holding audit evidence a
        # warning is not enough, so this is a hard startup failure.
        if self.JWT_ALGORITHM.startswith("HS"):
            key_bytes = len(self.JWT_SECRET_KEY.get_secret_value().encode())
            minimum = {"HS256": 32, "HS384": 48, "HS512": 64}[self.JWT_ALGORITHM]
            if key_bytes < minimum:
                raise ValueError(
                    f"JWT_SECRET_KEY is {key_bytes} bytes; {self.JWT_ALGORITHM} "
                    f"requires at least {minimum} (RFC 7518 s.3.2). This key is "
                    "shared with the main backend, so lengthen it there too."
                )

        if self.ES_API_KEY is None and not (self.ES_USERNAME and self.ES_PASSWORD):
            raise ValueError(
                "Elasticsearch credentials missing: set ES_API_KEY (preferred) "
                "or ES_USERNAME + ES_PASSWORD"
            )
        if self.DEFAULT_PAGE_SIZE > self.MAX_PAGE_SIZE:
            raise ValueError("DEFAULT_PAGE_SIZE cannot exceed MAX_PAGE_SIZE")
        return self

    # --------------------------------------------------------------- helpers
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT is Environment.PROD

    @property
    def dedicated_tenant_set(self) -> frozenset[str]:
        """O(1) membership test, consulted on every routing decision."""
        return frozenset(self.DEDICATED_TENANTS)

    def es_ssl_context(self) -> ssl.SSLContext | None:
        """Build a TLS context pinned to the cluster CA when one is supplied."""
        if not any(host.startswith("https://") for host in self.ES_HOSTS):
            return None
        context = ssl.create_default_context(cafile=self.ES_CA_CERT_PATH)
        if self.ES_VERIFY_CERTS:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            # Only reachable outside prod: the model validator blocks it there.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide singleton, cached so validation runs exactly once."""
    # Every field is populated from the environment, so the constructor takes
    # no arguments here.
    return Settings()
