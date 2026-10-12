-- name: UpsertImportRun :one
INSERT INTO import_run (tenant_id, scope_key, product_id, context_id, tool_name, scan_id, raw_key, raw_sha256, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'running')
ON CONFLICT (tenant_id, scope_key, tool_name, raw_sha256)
DO UPDATE SET status = 'running', started_at = now(), finished_at = NULL
WHERE import_run.status <> 'completed'
RETURNING id;
