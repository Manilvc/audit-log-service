"""Immutable WORM archive on S3 Object Lock.

What this adds over Elasticsearch
---------------------------------
The hash chain proves a *single* document was not altered in isolation. It does
not stop an attacker who owns the cluster from rewriting the whole tail of a
chain and recomputing every hash. Closing that hole needs one immutable
reference point, and that is what this module provides.

Segments of events are written to S3 with Object Lock in COMPLIANCE mode. In
that mode no principal - not an administrator, not the account root, not AWS
support - can delete or shorten the retention of an object before it expires.
A rewritten Elasticsearch tail therefore contradicts an object nobody can
change, and the tampering is provable rather than merely suspected.

The archive doubles as the disaster-recovery copy: if the cluster is lost
entirely, the audit trail can be rebuilt from these segments.

Object layout
-------------
    <prefix>/events/<tenant>/<yyyy>/<mm>/<dd>/<chain>/<start_seq>-<end_seq>.ndjson.gz
    <prefix>/checkpoints/<tenant>/<chain>/<seq>.json

NDJSON so a segment streams line by line without loading it whole, gzipped
because audit JSON is highly repetitive and compresses to roughly a fifth.
"""

from __future__ import annotations

import gzip
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import aioboto3
import orjson
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from app.core.config import Settings
from app.core.integrity import canonical_json, checkpoint_payload
from app.core.logging import get_logger

logger = get_logger(__name__)


class ArchiveError(RuntimeError):
    """The archive write failed.

    Raised rather than swallowed: if a segment cannot be sealed, the queue
    message must not be acknowledged, so the events are retried instead of
    silently existing only in a mutable store.
    """


@dataclass(frozen=True, slots=True)
class SealedSegment:
    """Result of sealing one segment."""

    key: str
    event_count: int
    bytes_written: int
    sha256: str
    retain_until: datetime


class WormArchive:
    """Writes tamper-proof segments and chain checkpoints to S3."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._session = aioboto3.Session(
            aws_access_key_id=(
                settings.AWS_ACCESS_KEY_ID.get_secret_value()
                if settings.AWS_ACCESS_KEY_ID
                else None
            ),
            aws_secret_access_key=(
                settings.AWS_SECRET_ACCESS_KEY.get_secret_value()
                if settings.AWS_SECRET_ACCESS_KEY
                else None
            ),
            region_name=settings.AWS_REGION,
        )
        # Retries are adaptive because a throttled archive write must not be
        # abandoned - the alternative is un-notarised evidence.
        self._boto_config = BotoConfig(
            retries={"max_attempts": 5, "mode": "adaptive"},
            signature_version="s3v4",
        )

    @property
    def enabled(self) -> bool:
        """True when archive writes are configured and should be attempted."""
        return self._settings.ARCHIVE_ENABLED and bool(self._settings.ARCHIVE_BUCKET)

    def _client(self) -> Any:
        """Lazy aioboto3 S3 client context (endpoint override for MinIO)."""
        return self._session.client(
            "s3",
            endpoint_url=self._settings.S3_ENDPOINT_URL,
            config=self._boto_config,
        )

    # -------------------------------------------------------------- verifying
    async def verify_bucket(self) -> dict[str, Any]:
        """Confirm Object Lock is actually switched on.

        Checked at startup because the failure is silent and total: writing to a
        bucket without Object Lock produces ordinary, deletable objects, and the
        service would report healthy while providing none of the immutability it
        claims. Object Lock can only be enabled at bucket creation, so this
        cannot be fixed after the fact.
        """
        if not self.enabled:
            return {"enabled": False}

        async with self._client() as s3:
            try:
                config = await s3.get_object_lock_configuration(
                    Bucket=self._settings.ARCHIVE_BUCKET
                )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in {"ObjectLockConfigurationNotFoundError", "InvalidRequest"}:
                    raise ArchiveError(
                        f"bucket {self._settings.ARCHIVE_BUCKET} does not have Object "
                        "Lock enabled, so archived audit segments would be deletable. "
                        "Object Lock can only be enabled when a bucket is created: "
                        "create a new bucket with ObjectLockEnabledForBucket=true."
                    ) from exc
                raise ArchiveError(f"cannot read Object Lock configuration: {exc}") from exc

            enabled = (
                config.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
            )
            if not enabled:
                raise ArchiveError(f"Object Lock is not Enabled on {self._settings.ARCHIVE_BUCKET}")

            # Object Lock protects each object *version*: a targeted
            # DeleteObjectVersion is refused ("WORM protected"), and COMPLIANCE
            # mode means nobody can shorten the retention. What it does not stop
            # is a plain DeleteObject, which on a versioned bucket writes a
            # zero-byte delete marker as the new current version. The locked data
            # is still there and still recoverable, but a default ListObjects or
            # GetObject then behaves as though the segment is gone - which for an
            # audit archive reads as missing evidence.
            #
            # Closing that gap needs a bucket policy denying s3:DeleteObject; see
            # deploy/s3-archive-bucket-policy.json. It cannot be verified from
            # here without s3:GetBucketPolicy, so the reminder is emitted once at
            # startup rather than silently assumed.
            logger.info(
                "worm_archive_delete_marker_note",
                bucket=self._settings.ARCHIVE_BUCKET,
                detail=(
                    "Object Lock protects object versions but does not block "
                    "delete markers. Apply deploy/s3-archive-bucket-policy.json "
                    "to deny s3:DeleteObject, or a plain DELETE will hide a "
                    "sealed segment from listings even though the version "
                    "survives."
                ),
            )

            return {
                "enabled": True,
                "bucket": self._settings.ARCHIVE_BUCKET,
                "mode": self._settings.OBJECT_LOCK_MODE,
                "retain_days": self._settings.OBJECT_LOCK_RETAIN_DAYS,
                "delete_marker_policy_required": True,
            }

    # ----------------------------------------------------------------- sealing
    async def seal_segment(
        self,
        *,
        tenant_id: str,
        chain_id: str,
        documents: list[dict[str, Any]],
    ) -> SealedSegment:
        """Write one immutable segment of audit documents.

        Documents are written in canonical form so a verifier re-reading the
        segment years later derives byte-identical hashes.
        """
        if not documents:
            raise ArchiveError("refusing to seal an empty segment")
        if not self.enabled:
            raise ArchiveError("archive is disabled; refusing to claim a sealed segment")

        seqs = [int((doc.get("integrity") or {}).get("seq", 0)) for doc in documents]
        start_seq, end_seq = min(seqs), max(seqs)

        body = gzip.compress(
            b"\n".join(canonical_json(doc) for doc in documents),
            # 6 is the knee of the curve for JSON: near-best ratio at a fraction
            # of the CPU of level 9, which matters on the ingest hot path.
            compresslevel=6,
        )
        digest = _sha256_hex(body)
        key = self._segment_key(tenant_id, chain_id, start_seq, end_seq)
        retain_until = datetime.now(UTC) + timedelta(days=self._settings.OBJECT_LOCK_RETAIN_DAYS)

        await self._put_locked_object(
            key=key,
            body=body,
            content_type="application/gzip",
            retain_until=retain_until,
            metadata={
                "tenant-id": tenant_id,
                "chain-id": chain_id,
                "start-seq": str(start_seq),
                "end-seq": str(end_seq),
                "event-count": str(len(documents)),
                "sha256": digest,
            },
        )

        logger.info(
            "segment_sealed",
            key=key,
            events=len(documents),
            bytes=len(body),
            chain_id=chain_id,
        )
        return SealedSegment(
            key=key,
            event_count=len(documents),
            bytes_written=len(body),
            sha256=digest,
            retain_until=retain_until,
        )

    async def seal_checkpoint(
        self,
        *,
        tenant_id: str,
        chain_id: str,
        seq: int,
        head_hash: str,
        event_count: int,
    ) -> str:
        """Notarise a chain head.

        This is the anchor the whole tamper-evidence argument rests on: a small,
        immutable record stating that at a given time, chain C had head H at
        sequence N. Any later rewrite of the chain is contradicted by an object
        that cannot be altered.
        """
        payload = checkpoint_payload(
            chain_id,
            seq=seq,
            head_hash=head_hash,
            sealed_at=datetime.now(UTC).isoformat(),
            event_count=event_count,
        )
        key = f"{self._settings.ARCHIVE_PREFIX}/checkpoints/{tenant_id}/{chain_id}/{seq}.json"
        await self._put_locked_object(
            key=key,
            body=orjson.dumps(payload, option=orjson.OPT_INDENT_2),
            content_type="application/json",
            retain_until=datetime.now(UTC) + timedelta(days=self._settings.OBJECT_LOCK_RETAIN_DAYS),
            metadata={"chain-id": chain_id, "seq": str(seq)},
        )
        logger.info("checkpoint_sealed", key=key, chain_id=chain_id, seq=seq)
        return key

    async def _put_locked_object(
        self,
        *,
        key: str,
        body: bytes,
        content_type: str,
        retain_until: datetime,
        metadata: dict[str, str],
    ) -> None:
        """PUT an object under Object Lock retention."""
        params: dict[str, Any] = {
            "Bucket": self._settings.ARCHIVE_BUCKET,
            "Key": key,
            "Body": body,
            "ContentType": content_type,
            "ObjectLockMode": self._settings.OBJECT_LOCK_MODE,
            "ObjectLockRetainUntilDate": retain_until,
            "Metadata": metadata,
            # Integrity on the wire: S3 rejects the upload if the checksum does
            # not match, so a corrupted transfer cannot become a sealed,
            # undeletable, corrupt object.
            "ChecksumAlgorithm": "SHA256",
        }
        if self._settings.ARCHIVE_KMS_KEY_ID:
            params["ServerSideEncryption"] = "aws:kms"
            params["SSEKMSKeyId"] = self._settings.ARCHIVE_KMS_KEY_ID
        elif not self._settings.S3_ENDPOINT_URL:
            # AES256 SSE is the default on real S3. MinIO (local endpoint) often
            # has no KMS/SSE configured and rejects the header with NotImplemented,
            # which would block the whole ingest path — skip SSE there.
            params["ServerSideEncryption"] = "AES256"

        async with self._client() as s3:
            try:
                await s3.put_object(**params)
            except ClientError as exc:
                raise ArchiveError(f"archive write failed for {key}: {exc}") from exc

    # ----------------------------------------------------------------- reading
    async def read_segment(self, key: str) -> list[dict[str, Any]]:
        """Read a segment back, for verification or disaster recovery."""
        async with self._client() as s3:
            try:
                response = await s3.get_object(Bucket=self._settings.ARCHIVE_BUCKET, Key=key)
                raw = await response["Body"].read()
            except ClientError as exc:
                raise ArchiveError(f"archive read failed for {key}: {exc}") from exc

        lines = gzip.decompress(raw).split(b"\n")
        return [orjson.loads(line) for line in lines if line]

    async def latest_checkpoint(self, *, tenant_id: str, chain_id: str) -> dict[str, Any] | None:
        """Most recent notarised checkpoint for a chain.

        Keys end in the zero-padded sequence number, so lexicographic order
        equals numeric order and the last key S3 lists is the newest.
        """
        prefix = f"{self._settings.ARCHIVE_PREFIX}/checkpoints/{tenant_id}/{chain_id}/"
        async with self._client() as s3:
            paginator = s3.get_paginator("list_objects_v2")
            newest: str | None = None
            async for page in paginator.paginate(
                Bucket=self._settings.ARCHIVE_BUCKET, Prefix=prefix
            ):
                for entry in page.get("Contents", []):
                    key = entry["Key"]
                    if newest is None or _seq_of_key(key) > _seq_of_key(newest):
                        newest = key
            if newest is None:
                return None
            response = await s3.get_object(Bucket=self._settings.ARCHIVE_BUCKET, Key=newest)
            return dict(orjson.loads(await response["Body"].read()))

    # ----------------------------------------------------------------- helpers
    def _segment_key(self, tenant_id: str, chain_id: str, start: int, end: int) -> str:
        now = datetime.now(UTC)
        safe_chain = chain_id.replace(":", "_")
        # Sequence numbers are zero-padded so lexicographic listing matches
        # numeric order - S3 has no numeric sort.
        return (
            f"{self._settings.ARCHIVE_PREFIX}/events/{tenant_id}/"
            f"{now:%Y/%m/%d}/{safe_chain}/{start:018d}-{end:018d}.ndjson.gz"
        )


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _seq_of_key(key: str) -> int:
    """Extract the trailing sequence number from a checkpoint key."""
    stem = key.rsplit("/", 1)[-1].removesuffix(".json")
    try:
        return int(stem)
    except ValueError:
        return -1
