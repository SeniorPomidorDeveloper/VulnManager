MISSING_RUN = '00000000-0000-0000-0000-000000000000'
INSERT_RUN = (
    'INSERT INTO import_run (tenant_id, scope_key, product_id, context_id, '
    'tool_name, scan_id, raw_key, raw_sha256, status) '
    "VALUES ('acme', 'scope', 'p', 'c', 'trivy', 's', 'key', 'sha', %s) "
    'RETURNING id'
)
INSERT_FINDING = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at) '
    "VALUES ('acme', %s, 'scope', 'p', 'c', 'id', 'sca', 't', 'd', 'HIGH', "
    "'{}', '{}', 'trivy@1', now())"
)
INSERT_FINDING_SEVERITY = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at, severity) '
    "VALUES ('acme', %s, 'scope', 'p', 'c', 'id', 'sca', 't', 'd', 'HIGH', "
    "'{}', '{}', 'trivy@1', now(), %s)"
)
INSERT_FINDING_VULN = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at, vuln_source, vuln_id) '
    "VALUES ('acme', %s, 'scope', 'p', 'c', 'id', 'sca', 't', 'd', 'HIGH', "
    "'{}', '{}', 'trivy@1', now(), %s, %s)"
)
