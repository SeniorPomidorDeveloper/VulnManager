CREATE TABLE finding_cvss (
    tenant_id  text             NOT NULL,
    finding_id uuid             NOT NULL REFERENCES finding (id),
    source     text             NOT NULL,
    version    text             NOT NULL CHECK (version IN ('2.0', '3.0', '3.1')),
    vector     text             NOT NULL,
    score      double precision NOT NULL CHECK (score BETWEEN 0 AND 10),
    PRIMARY KEY (tenant_id, finding_id, source, vector)
);

CREATE INDEX finding_cvss_score_idx ON finding_cvss (tenant_id, source, score DESC);
