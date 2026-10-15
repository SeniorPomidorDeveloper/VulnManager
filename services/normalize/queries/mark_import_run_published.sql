-- name: MarkImportRunPublished :execrows
UPDATE import_run
SET event_published_at = now()
WHERE tenant_id = $1 AND id = $2 AND status = 'completed' AND event_published_at IS NULL;
