-- name: LookupFingerprints :many
WITH k AS (
    SELECT unnest(sqlc.arg(levels)::text[]) AS level, unnest(sqlc.arg(values)::text[]) AS value
)
SELECT ff.finding_id, ff.level, ff.value
FROM k
JOIN finding_fingerprint ff ON ff.level = k.level AND ff.value = k.value
WHERE ff.tenant_id = sqlc.arg(tenant_id)::text AND ff.scope_key = sqlc.arg(scope_key)::text;
