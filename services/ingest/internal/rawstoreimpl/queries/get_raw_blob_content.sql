-- name: GetRawBlobContent :one
SELECT content FROM raw_blob WHERE tenant_id = $1 AND scan_id = $2 AND sha256 = $3;
