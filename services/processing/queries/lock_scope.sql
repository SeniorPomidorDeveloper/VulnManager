-- name: LockScope :exec
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(scope_key)::text, 0));
