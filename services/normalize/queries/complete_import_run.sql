-- name: CompleteImportRun :exec
UPDATE import_run
SET status = 'completed', finished_at = now(), stats = $2
WHERE id = $1;
