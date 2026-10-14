ALTER TABLE finding
    ADD COLUMN severity_rank smallint GENERATED ALWAYS AS (
        CASE severity
            WHEN 'info' THEN 1
            WHEN 'unknown' THEN 2
            WHEN 'low' THEN 3
            WHEN 'medium' THEN 4
            WHEN 'high' THEN 5
            WHEN 'critical' THEN 6
        END
    ) STORED;

CREATE INDEX finding_severity_rank_idx ON finding (tenant_id, scope_key, severity_rank DESC);
