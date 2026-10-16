-- name: ListRunFindings :many
SELECT f.id, f.tool_finding_id, COALESCE(f.provenance->>'tool', '')::text AS tool, f.kind, f.severity, f.rule_id, f.vuln_source, f.vuln_id, f.location,
       c.purl, c.type AS component_type, c.namespace, c.name, c.version,
       COALESCE((
           SELECT array_agg(w.cwe ORDER BY w.cwe) FROM finding_cwe w
           WHERE w.tenant_id = f.tenant_id AND w.finding_id = f.id
       ), '{}')::text[] AS cwe
FROM finding f
LEFT JOIN component c ON c.id = f.component_id
WHERE f.tenant_id = $1 AND f.import_run_id = $2
ORDER BY f.id;
