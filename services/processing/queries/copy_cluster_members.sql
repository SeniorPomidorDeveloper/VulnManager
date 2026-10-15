-- name: CopyClusterMembers :copyfrom
INSERT INTO cluster_member (tenant_id, cluster_id, finding_id, confidence, reasons, algo_version)
VALUES ($1, $2, $3, $4, $5, $6);
