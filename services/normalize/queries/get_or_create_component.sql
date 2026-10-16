-- name: GetOrCreateComponent :one
WITH inserted AS (
    INSERT INTO component (tenant_id, purl, type, namespace, name, version)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT (tenant_id, purl) DO NOTHING
    RETURNING id
)
SELECT id FROM inserted
UNION ALL
SELECT id FROM component WHERE tenant_id = $1 AND purl = $2
LIMIT 1;
