-- name: PutRawBlob :exec
INSERT INTO raw_blob (tenant_id, scan_id, sha256, content, size_bytes)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, scan_id, sha256) DO NOTHING;
