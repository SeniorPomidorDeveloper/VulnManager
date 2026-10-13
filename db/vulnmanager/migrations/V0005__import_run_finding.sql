CREATE TABLE import_run (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    text        NOT NULL,
    scope_key    text        NOT NULL,
    product_id   text        NOT NULL,
    context_id   text        NOT NULL,
    tool_name    text        NOT NULL,
    scan_id      text        NOT NULL,
    raw_key      text        NOT NULL,
    raw_sha256   text        NOT NULL,
    status       text        NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'partial')),
    completeness text        NOT NULL DEFAULT 'full' CHECK (completeness IN ('full', 'partial')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    stats        jsonb       NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX import_run_report_key_idx ON import_run (tenant_id, scope_key, tool_name, raw_sha256);

CREATE TABLE finding (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text        NOT NULL,
    import_run_id   uuid        NOT NULL REFERENCES import_run (id),
    scope_key       text        NOT NULL,
    product_id      text        NOT NULL,
    context_id      text        NOT NULL,
    tool_finding_id text        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('unknown', 'sast', 'dast', 'sca', 'secret', 'iac', 'container')),
    title           text        NOT NULL,
    description     text        NOT NULL,
    severity_raw    text        NOT NULL,
    location        jsonb,
    raw             jsonb       NOT NULL,
    provenance      jsonb       NOT NULL,
    algo_version    text        NOT NULL,
    diagnostics     jsonb       NOT NULL DEFAULT '[]',
    detected_at     timestamptz NOT NULL
);

CREATE INDEX finding_run_idx ON finding (tenant_id, import_run_id);

ALTER TABLE import_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE import_run FORCE ROW LEVEL SECURITY;
CREATE POLICY import_run_tenant_isolation ON import_run
    USING (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE finding ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding FORCE ROW LEVEL SECURITY;
CREATE POLICY finding_tenant_isolation ON finding
    USING (tenant_id = current_setting('app.tenant_id', true));
