-- name: FinishIngestJob :one
SELECT finish_ingest_job($1, $2, $3, $4);
