-- name: InsertFinding :exec
INSERT INTO finding (
    tenant_id, import_run_id, scope_key, product_id, context_id, tool_finding_id, kind, title,
    description, severity_raw, severity, location, raw, provenance, algo_version, diagnostics, detected_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17);
