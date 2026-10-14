-- name: UpsertComponent :one
INSERT INTO component (tenant_id, purl, type, namespace, name, version)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, purl)
DO UPDATE SET purl = EXCLUDED.purl
RETURNING id;
