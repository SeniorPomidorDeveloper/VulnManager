-- name: CopyFindingFingerprints :copyfrom
INSERT INTO finding_fingerprint (tenant_id, finding_id, scope_key, level, strategy, version, value)
VALUES ($1, $2, $3, $4, $5, $6, $7);
