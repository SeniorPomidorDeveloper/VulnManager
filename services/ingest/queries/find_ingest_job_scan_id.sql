-- name: FindIngestJobScanID :one
SELECT scan_id FROM ingest_job
WHERE tenant_id = $1 AND scope_key = $2 AND tool = $3 AND sha256 = $4;
