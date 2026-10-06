CREATE TABLE tenant (
    id               text   PRIMARY KEY,
    max_report_bytes bigint NOT NULL CHECK (max_report_bytes > 0)
);

CREATE TABLE product (
    tenant_id text NOT NULL,
    id        text NOT NULL,
    scope_key text NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, scope_key)
);

CREATE TABLE ingest_job (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    text        NOT NULL,
    scope_key    text        NOT NULL,
    raw_key      text        NOT NULL,
    state        text        NOT NULL DEFAULT 'pending'
                             CHECK (state IN ('pending', 'running', 'done', 'dead')),
    attempts     integer     NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    locked_by    text,
    locked_until timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ingest_job_tenant_state_idx ON ingest_job (tenant_id, state);
CREATE INDEX ingest_job_pending_idx ON ingest_job (tenant_id, available_at) WHERE state = 'pending';

ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant
    USING (id = current_setting('app.tenant_id', true));

ALTER TABLE product ENABLE ROW LEVEL SECURITY;
ALTER TABLE product FORCE ROW LEVEL SECURITY;
CREATE POLICY product_tenant_isolation ON product
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE ingest_job ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_job FORCE ROW LEVEL SECURITY;
CREATE POLICY ingest_job_tenant_isolation ON ingest_job
    USING (tenant_id = current_setting('app.tenant_id', true));
