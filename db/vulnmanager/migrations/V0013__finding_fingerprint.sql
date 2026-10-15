CREATE TABLE finding_fingerprint (
    tenant_id  text    NOT NULL,
    finding_id uuid    NOT NULL REFERENCES finding (id),
    scope_key  text    NOT NULL,
    level      text    NOT NULL CHECK (level IN ('l0', 'l1', 'l2')),
    strategy   text    NOT NULL,
    version    integer NOT NULL CHECK (version > 0),
    value      text    NOT NULL,
    PRIMARY KEY (tenant_id, finding_id, level)
);

CREATE INDEX finding_fingerprint_block_idx ON finding_fingerprint (tenant_id, scope_key, level, value);

CREATE TABLE processing_run (
    tenant_id     text        NOT NULL,
    import_run_id uuid        NOT NULL REFERENCES import_run (id),
    algo_version  text        NOT NULL,
    processed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, import_run_id)
);
