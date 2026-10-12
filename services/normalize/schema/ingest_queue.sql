CREATE TABLE ingest_queue_job (
    id         uuid    NOT NULL,
    tenant_id  text    NOT NULL,
    product_id text    NOT NULL,
    context_id text    NOT NULL,
    tool       text    NOT NULL,
    scan_id    text    NOT NULL,
    sha256     text    NOT NULL,
    attempts   integer NOT NULL
);

CREATE FUNCTION claim_ingest_job(p_worker text, p_lease interval)
RETURNS SETOF ingest_queue_job
LANGUAGE sql
AS $$ SELECT * FROM ingest_queue_job WHERE false $$;

CREATE FUNCTION finish_ingest_job(p_id uuid, p_worker text, p_state text, p_retry_after interval)
RETURNS boolean
LANGUAGE sql
AS $$ SELECT false $$;
