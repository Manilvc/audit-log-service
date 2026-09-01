#!/usr/bin/env bash
#
# Create the local WORM bucket in MinIO.
#
# Object Lock can ONLY be enabled at bucket creation time - there is no way to
# turn it on afterwards, in MinIO or in real S3. That is why this is a separate
# provisioning step rather than something the service does at startup: if the
# bucket already exists without Object Lock, the only fix is a new bucket.
set -euo pipefail

ENDPOINT="${S3_ENDPOINT_URL:-http://localhost:9000}"
BUCKET="${ARCHIVE_BUCKET:-everycred-audit-archive-local}"
ACCESS_KEY="${AWS_ACCESS_KEY_ID:-minioadmin}"
SECRET_KEY="${AWS_SECRET_ACCESS_KEY:-minioadmin123}"
RETAIN_DAYS="${OBJECT_LOCK_RETAIN_DAYS:-2190}"

echo "Configuring MinIO at ${ENDPOINT}"

# Run mc in a container so no local install is required.
mc() {
  docker run --rm --network host \
    -e "MC_HOST_local=http://${ACCESS_KEY}:${SECRET_KEY}@${ENDPOINT#http://}" \
    minio/mc:latest "$@"
}

if mc ls "local/${BUCKET}" >/dev/null 2>&1; then
  echo "Bucket ${BUCKET} already exists."
  # Verify rather than assume: a bucket created without --with-lock provides
  # none of the immutability the service reports as active.
  if mc retention info "local/${BUCKET}" 2>/dev/null | grep -qi "compliance\|governance"; then
    echo "  Object Lock: enabled"
  else
    echo "  WARNING: Object Lock is NOT enabled on ${BUCKET}."
    echo "  Archived segments would be deletable, so the WORM guarantee does not hold."
    echo "  Object Lock cannot be added to an existing bucket - create a new one:"
    echo "    ARCHIVE_BUCKET=${BUCKET}-v2 ./scripts/init-minio.sh"
    exit 1
  fi
else
  echo "Creating ${BUCKET} with Object Lock..."
  mc mb --with-lock "local/${BUCKET}"
  # Default retention, so an object is locked even if a client omits the
  # per-object header. Defence in depth: the service always sets it explicitly.
  mc retention set --default COMPLIANCE "${RETAIN_DAYS}d" "local/${BUCKET}"
  # Versioning is implied by Object Lock, but set explicitly so the intent is
  # visible in the bucket configuration.
  mc version enable "local/${BUCKET}"
  echo "  Object Lock: COMPLIANCE, ${RETAIN_DAYS} days"
fi

echo
echo "Done. Note: MinIO's COMPLIANCE mode is a weaker guarantee than S3's -"
echo "real S3 COMPLIANCE cannot be overridden even by the account root."
