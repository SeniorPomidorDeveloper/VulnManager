-- name: ClaimIngestJob :one
SELECT id, tenant_id, product_id, context_id, tool, scan_id, sha256, attempts
FROM claim_ingest_job($1, $2);
