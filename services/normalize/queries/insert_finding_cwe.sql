-- name: InsertFindingCWE :exec
INSERT INTO finding_cwe (tenant_id, finding_id, cwe)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;
