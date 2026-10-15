-- name: LookupFingerprints :many
SELECT finding_id, level, value
FROM finding_fingerprint
WHERE tenant_id = $1 AND scope_key = $2 AND level = ANY(sqlc.arg(levels)::text[]) AND value = ANY(sqlc.arg(values)::text[]);
