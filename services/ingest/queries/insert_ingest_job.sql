-- name: InsertIngestJob :execrows
INSERT INTO ingest_job (tenant_id, scope_key, raw_key, tool, sha256, scan_id)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, scope_key, tool, sha256) DO NOTHING;
