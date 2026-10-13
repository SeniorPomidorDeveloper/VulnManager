ALTER TABLE ingest_job ADD COLUMN product_id text NOT NULL DEFAULT '';
ALTER TABLE ingest_job ADD COLUMN context_id text NOT NULL DEFAULT '';

ALTER TABLE ingest_job ALTER COLUMN product_id DROP DEFAULT;
ALTER TABLE ingest_job ALTER COLUMN context_id DROP DEFAULT;
