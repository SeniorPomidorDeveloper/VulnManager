-- name: ClusterOfFindings :many
SELECT finding_id, cluster_id
FROM cluster_member
WHERE tenant_id = $1 AND finding_id = ANY(sqlc.arg(ids)::uuid[]);
