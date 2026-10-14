-- name: InsertFindingRating :exec
INSERT INTO finding_rating (tenant_id, finding_id, source, scheme, version, vector, score)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT DO NOTHING;
