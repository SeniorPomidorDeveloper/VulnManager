ALTER TABLE ingest_job ADD COLUMN product_id text NOT NULL DEFAULT '';
ALTER TABLE ingest_job ADD COLUMN context_id text NOT NULL DEFAULT '';

ALTER TABLE ingest_job ALTER COLUMN product_id DROP DEFAULT;
ALTER TABLE ingest_job ALTER COLUMN context_id DROP DEFAULT;

CREATE FUNCTION claim_ingest_job(p_worker text, p_lease interval)
RETURNS TABLE (
    id uuid,
    tenant_id text,
    scope_key text,
    product_id text,
    context_id text,
    tool text,
    scan_id text,
    sha256 text,
    raw_key text,
    attempts integer
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    UPDATE ingest_job AS j
    SET state = 'running',
        attempts = j.attempts + 1,
        locked_by = p_worker,
        locked_until = now() + p_lease
    WHERE j.id = (
        SELECT c.id
        FROM ingest_job AS c
        WHERE (c.state = 'pending' AND c.available_at <= now())
           OR (c.state = 'running' AND c.locked_until <= now())
        ORDER BY c.available_at, c.created_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING j.id, j.tenant_id, j.scope_key, j.product_id, j.context_id,
              j.tool, j.scan_id, j.sha256, j.raw_key, j.attempts
$$;

CREATE FUNCTION finish_ingest_job(
    p_id uuid,
    p_worker text,
    p_state text,
    p_retry_after interval DEFAULT '0 seconds'
)
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH updated AS (
        UPDATE ingest_job
        SET state = p_state,
            available_at = now() + p_retry_after,
            locked_by = NULL,
            locked_until = NULL
        WHERE id = p_id AND locked_by = p_worker AND state = 'running'
        RETURNING 1
    )
    SELECT EXISTS (SELECT 1 FROM updated)
$$;

ALTER FUNCTION claim_ingest_job(text, interval) OWNER TO ingest_queue_owner;
ALTER FUNCTION finish_ingest_job(uuid, text, text, interval) OWNER TO ingest_queue_owner;

GRANT SELECT, UPDATE ON ingest_job TO ingest_queue_owner;

REVOKE ALL ON FUNCTION claim_ingest_job(text, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION finish_ingest_job(uuid, text, text, interval) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION claim_ingest_job(text, interval) TO queue_consumer;
GRANT EXECUTE ON FUNCTION finish_ingest_job(uuid, text, text, interval) TO queue_consumer;
