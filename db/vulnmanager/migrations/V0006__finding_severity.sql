ALTER TABLE finding
    ADD COLUMN severity text NOT NULL DEFAULT 'unknown'
    CHECK (severity IN ('unknown', 'info', 'low', 'medium', 'high', 'critical'));
