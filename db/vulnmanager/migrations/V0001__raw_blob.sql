CREATE TABLE raw_blob (
    tenant_id  text        NOT NULL,
    scan_id    text        NOT NULL,
    sha256     text        NOT NULL,
    content    bytea       NOT NULL,
    size_bytes bigint      NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, scan_id, sha256)
);
