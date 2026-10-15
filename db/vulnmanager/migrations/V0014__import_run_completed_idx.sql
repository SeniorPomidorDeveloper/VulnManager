CREATE INDEX import_run_completed_idx ON import_run (finished_at) WHERE status = 'completed';
