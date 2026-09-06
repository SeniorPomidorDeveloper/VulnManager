CREATE TABLE raw_blob (
    tenant_id  text        NOT NULL,
    scan_id    text        NOT NULL,
    sha256     text        NOT NULL,
    content    bytea       NOT NULL,
    size_bytes bigint      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, scan_id, sha256)
);

ALTER TABLE raw_blob ENABLE ROW LEVEL SECURITY;
ALTER TABLE raw_blob FORCE ROW LEVEL SECURITY;

CREATE POLICY raw_blob_tenant_isolation ON raw_blob
    USING (tenant_id = current_setting('app.tenant_id', true));
