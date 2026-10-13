-- name: GetIngestJobState :one
SELECT state FROM ingest_job WHERE id = $1;
