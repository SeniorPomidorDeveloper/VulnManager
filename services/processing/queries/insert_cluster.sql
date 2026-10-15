-- name: InsertCluster :one
INSERT INTO cluster (tenant_id, scope_key, algo_version)
VALUES ($1, $2, $3)
RETURNING id;
