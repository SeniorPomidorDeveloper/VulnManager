-- name: ClaimIngestJob :one
UPDATE ingest_job
SET state = 'running',
    attempts = attempts + 1,
    locked_by = @worker,
    locked_until = now() + @lease::interval
WHERE id = @id
  AND (state = 'pending' OR (state = 'running' AND locked_until <= now()))
RETURNING id, tenant_id, product_id, context_id, tool, scan_id, sha256, attempts;
