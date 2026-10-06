-- name: InsertIngestJob :exec
INSERT INTO ingest_job (tenant_id, scope_key, raw_key)
VALUES ($1, $2, $3);
