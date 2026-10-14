CREATE TABLE finding_rating (
    tenant_id  text             NOT NULL,
    finding_id uuid             NOT NULL REFERENCES finding (id),
    source     text             NOT NULL,
    scheme     text             NOT NULL,
    version    text             NOT NULL DEFAULT '',
    vector     text             NOT NULL DEFAULT '',
    score      double precision NOT NULL CHECK (score >= 0),
    PRIMARY KEY (tenant_id, finding_id, source, scheme, version, vector)
);

CREATE INDEX finding_rating_score_idx ON finding_rating (tenant_id, scheme, source, score DESC);
