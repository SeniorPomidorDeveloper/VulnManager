ALTER TABLE import_run ADD COLUMN event_published_at timestamptz;

CREATE INDEX import_run_unpublished_idx ON import_run (tenant_id, finished_at)
    WHERE status = 'completed' AND event_published_at IS NULL;
