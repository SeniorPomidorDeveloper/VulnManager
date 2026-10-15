-- name: UnprocessedImportRuns :one
SELECT
    count(*)::bigint AS runs,
    COALESCE(EXTRACT(EPOCH FROM (now() - min(r.finished_at))), 0)::float8 AS oldest_age_seconds
FROM import_run r
WHERE r.status = 'completed'
  AND r.finished_at > now() - make_interval(secs => sqlc.arg(window_seconds)::float8)
  AND NOT EXISTS (
      SELECT 1 FROM processing_run p WHERE p.tenant_id = r.tenant_id AND p.import_run_id = r.id
  );
