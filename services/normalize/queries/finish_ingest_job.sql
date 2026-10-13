-- name: FinishIngestJob :execrows
UPDATE ingest_job
SET state = @state,
    locked_by = NULL,
    locked_until = NULL
WHERE id = @id AND locked_by = @worker AND state = 'running';
