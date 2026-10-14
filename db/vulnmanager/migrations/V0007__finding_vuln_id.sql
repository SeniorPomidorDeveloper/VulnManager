ALTER TABLE finding
    ADD COLUMN vuln_source text,
    ADD COLUMN vuln_id text,
    ADD CONSTRAINT finding_vuln_id_pair CHECK ((vuln_source IS NULL) = (vuln_id IS NULL));
