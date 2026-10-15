-- name: ListRunFindings :many
SELECT f.id, f.tool_finding_id, f.kind, f.rule_id, f.vuln_source, f.vuln_id, f.location,
       c.purl, c.type AS component_type, c.namespace, c.name, c.version
FROM finding f
LEFT JOIN component c ON c.id = f.component_id
WHERE f.tenant_id = $1 AND f.import_run_id = $2
ORDER BY f.id;
