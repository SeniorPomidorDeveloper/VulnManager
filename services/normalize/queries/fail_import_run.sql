-- name: FailImportRun :exec
INSERT INTO import_run (tenant_id, scope_key, product_id, context_id, tool_name, scan_id, raw_key, raw_sha256, status, finished_at, stats)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'failed', now(), $9)
ON CONFLICT (tenant_id, scope_key, tool_name, raw_sha256)
DO UPDATE SET status = 'failed', finished_at = now(), stats = $9
WHERE import_run.status <> 'completed';
