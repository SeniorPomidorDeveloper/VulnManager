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
INSERT_COMPONENT = (
    'INSERT INTO component (tenant_id, purl, type, name, version) '
    "VALUES (%s, 'pkg:npm/lodash@4.17.21', 'npm', 'lodash', '4.17.21') "
    'RETURNING id'
)
UPSERT_COMPONENT = (
    'INSERT INTO component (tenant_id, purl, type, namespace, name, version) '
    "VALUES (%s, 'pkg:npm/lodash@4.17.21', 'npm', '', 'lodash', '4.17.21') "
    'ON CONFLICT (tenant_id, purl) DO UPDATE SET purl = EXCLUDED.purl '
    'RETURNING id'
)
INSERT_FINDING_COMPONENT = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at, component_id) '
    "VALUES ('acme', %s, 'scope', 'p', 'c', 'id', 'sca', 't', 'd', 'HIGH', "
    "'{}', '{}', 'trivy@1', now(), %s)"
)
INSERT_RATING = (
    'INSERT INTO finding_rating (tenant_id, finding_id, source, scheme, '
    'version, vector, score) '
    "VALUES ('acme', %s, %s, %s, %s, %s, %s)"
)
INSERT_CWE = (
    'INSERT INTO finding_cwe (tenant_id, finding_id, cwe) '
    "VALUES ('acme', %s, %s)"
)
INSERT_FINDING_RULE = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at, rule_id) '
    "VALUES ('acme', %s, 'scope', 'p', 'c', 'id', 'sast', 't', 'd', 'HIGH', "
    "'{}', '{}', 'semgrep@1', now(), %s)"
)
