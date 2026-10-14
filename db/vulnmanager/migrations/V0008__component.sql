CREATE TABLE component (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL,
    purl      text NOT NULL,
    type      text NOT NULL,
    namespace text NOT NULL DEFAULT '',
    name      text NOT NULL,
    version   text NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX component_purl_idx ON component (tenant_id, purl);

ALTER TABLE finding ADD COLUMN component_id uuid REFERENCES component (id);

CREATE INDEX finding_component_idx ON finding (tenant_id, component_id) WHERE component_id IS NOT NULL;
