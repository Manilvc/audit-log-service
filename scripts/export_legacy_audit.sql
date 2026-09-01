-- Example export for historical backfill into the audit microservice.
-- Run per tenant database. Pipe results to NDJSON (psql \copy / client tooling).
--
-- Required columns for the audit-service backfill mapper:
--   source, tenant_id, uuid, ...table-specific fields

-- user_audit_log
SELECT json_build_object(
  'source', 'user_audit_log',
  'tenant_id', :'tenant_id',
  'uuid', uuid,
  'user_id', user_id,
  'user_uuid', user_uuid,
  'issuer_id', issuer_id,
  'issuer_uuid', issuer_uuid,
  'entity', entity,
  'action', action,
  'status', status,
  'details', details,
  'record_uuids', record_uuids,
  'ip_address', ip_address,
  'location_country', location_country,
  'location_city', location_city,
  'browser_name', browser_name,
  'browser_version', browser_version,
  'device', device,
  'created_at', created_at
)
FROM user_audit_log
ORDER BY created_at ASC;

-- holder_audit_log
-- SELECT json_build_object(
--   'source', 'holder_audit_log',
--   'tenant_id', :'tenant_id',
--   'uuid', uuid,
--   'holder_id', holder_id,
--   'holder_uuid', holder_uuid,
--   'entity', entity,
--   'action', action,
--   'status', status,
--   'details', details,
--   'record_uuids', record_uuids,
--   'created_at', created_at
-- )
-- FROM holder_audit_log
-- ORDER BY created_at ASC;

-- session_audit_log
-- SELECT json_build_object(
--   'source', 'session_audit_log',
--   'tenant_id', :'tenant_id',
--   'id', id,
--   'session_uuid', session_uuid,
--   'user_id', user_id,
--   'event_type', event_type,
--   'ip_address', ip_address,
--   'location_country_code', location_country_code,
--   'actor_user_id', actor_user_id,
--   'metadata_json', metadata_json,
--   'created_at', created_at
-- )
-- FROM session_audit_log
-- ORDER BY created_at ASC;
