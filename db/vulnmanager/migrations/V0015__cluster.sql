CREATE TABLE cluster (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    text        NOT NULL,
    scope_key    text        NOT NULL,
    algo_version text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX cluster_scope_idx ON cluster (tenant_id, scope_key);

CREATE TABLE cluster_member (
    tenant_id    text         NOT NULL,
    cluster_id   uuid         NOT NULL REFERENCES cluster (id),
    finding_id   uuid         NOT NULL REFERENCES finding (id),
    confidence   numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    reasons      jsonb        NOT NULL DEFAULT '[]',
    algo_version text         NOT NULL,
    decided_at   timestamptz  NOT NULL DEFAULT now(),
    decided_by   text         NOT NULL DEFAULT 'algo' CHECK (decided_by IN ('algo', 'analyst')),
    PRIMARY KEY (tenant_id, cluster_id, finding_id)
);

CREATE UNIQUE INDEX cluster_member_finding_idx ON cluster_member (tenant_id, finding_id);
