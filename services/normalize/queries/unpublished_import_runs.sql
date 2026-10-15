-- name: UnpublishedImportRuns :one
SELECT
    count(*)::bigint AS runs,
    COALESCE(EXTRACT(EPOCH FROM (now() - min(finished_at))), 0)::float8 AS oldest_age_seconds
FROM import_run
WHERE status = 'completed' AND event_published_at IS NULL;
