ALTER TABLE ingest_job ADD COLUMN tool text NOT NULL DEFAULT '';
ALTER TABLE ingest_job ADD COLUMN sha256 text NOT NULL DEFAULT '';
ALTER TABLE ingest_job ADD COLUMN scan_id text NOT NULL DEFAULT '';

ALTER TABLE ingest_job ALTER COLUMN tool DROP DEFAULT;
ALTER TABLE ingest_job ALTER COLUMN sha256 DROP DEFAULT;
ALTER TABLE ingest_job ALTER COLUMN scan_id DROP DEFAULT;

CREATE UNIQUE INDEX ingest_job_report_key_idx ON ingest_job (tenant_id, scope_key, tool, sha256);
