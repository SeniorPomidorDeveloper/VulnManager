-- name: GetImportRun :one
SELECT scope_key, product_id, context_id, tool_name, status
FROM import_run
WHERE tenant_id = $1 AND id = $2;
