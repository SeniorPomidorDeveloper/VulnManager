ALTER TABLE finding ADD COLUMN rule_id text;

CREATE TABLE finding_cwe (
    tenant_id  text NOT NULL,
    finding_id uuid NOT NULL REFERENCES finding (id),
    cwe        text NOT NULL CHECK (cwe ~ '^CWE-[1-9][0-9]*$'),
    PRIMARY KEY (tenant_id, finding_id, cwe)
);

CREATE INDEX finding_cwe_idx ON finding_cwe (tenant_id, cwe);
