-- name: UnpublishedImportRun :one
SELECT id
FROM import_run
WHERE tenant_id = $1 AND scope_key = $2 AND tool_name = $3 AND raw_sha256 = $4
  AND status = 'completed' AND event_published_at IS NULL;
