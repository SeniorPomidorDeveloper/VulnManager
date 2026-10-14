-- name: InsertFindingCVSS :exec
INSERT INTO finding_cvss (tenant_id, finding_id, source, version, vector, score)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT DO NOTHING;
