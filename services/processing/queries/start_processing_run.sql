-- name: StartProcessingRun :execrows
INSERT INTO processing_run (tenant_id, import_run_id, algo_version)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, import_run_id) DO NOTHING;
