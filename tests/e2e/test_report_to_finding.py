import json
import uuid

import client
import pytest
import settings

ACCEPTED = 202
TRIVY = 'trivy'
FINDINGS = (
    'SELECT count(*) FROM finding f JOIN import_run r '
    'ON r.id = f.import_run_id AND r.tenant_id = f.tenant_id '
    'WHERE r.raw_sha256 = %s'
)
COMPONENTS = (
    'SELECT count(f.component_id), count(DISTINCT f.component_id) '
    'FROM finding f JOIN import_run r '
    'ON r.id = f.import_run_id AND r.tenant_id = f.tenant_id '
    'WHERE r.raw_sha256 = %s'
)
VERSIONS = (
    "SELECT string_agg(DISTINCT f.provenance->>'tool_version', ',') "
    'FROM finding f JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s'
)
CWES = (
    'SELECT count(*), count(DISTINCT c.finding_id) FROM finding_cwe c '
    'JOIN finding f ON f.id = c.finding_id AND f.tenant_id = c.tenant_id '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id '
    'WHERE r.raw_sha256 = %s'
)
CVSS_SCORES = (
    'SELECT count(*), count(DISTINCT c.finding_id) FROM finding_rating c '
    'JOIN finding f ON f.id = c.finding_id AND f.tenant_id = c.tenant_id '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id '
    "WHERE c.scheme = 'cvss' AND r.raw_sha256 = %s"
)


def unique_report():
    report = json.loads(settings.CORPUS.read_text())
    report['ReportID'] = str(uuid.uuid4())
    return json.dumps(report).encode()


@pytest.fixture(scope='module')
def trivy_sha(database):
    status, answer = client.send(unique_report(), TRIVY)
    assert status == ACCEPTED
    return client.completed(database, answer)


def test_trivy_report_becomes_findings(database, trivy_sha):
    assert client.fetch_one(database, FINDINGS, trivy_sha) == (
        settings.EXPECTED_FINDINGS,
    )


def test_trivy_findings_share_components(database, trivy_sha):
    assert client.fetch_one(database, COMPONENTS, trivy_sha) == (
        settings.EXPECTED_FINDINGS,
        settings.EXPECTED_COMPONENTS,
    )


def test_trivy_findings_keep_cvss_per_source(database, trivy_sha):
    assert client.fetch_one(database, CVSS_SCORES, trivy_sha) == (
        settings.EXPECTED_CVSS_ROWS,
        settings.EXPECTED_CVSS_FINDINGS,
    )


def test_trivy_findings_keep_normalized_cwe(database, trivy_sha):
    assert client.fetch_one(database, CWES, trivy_sha) == (
        settings.EXPECTED_CWE_ROWS,
        settings.EXPECTED_CWE_FINDINGS,
    )


def test_trivy_findings_record_the_tool_version(database, trivy_sha):
    assert client.fetch_one(database, VERSIONS, trivy_sha) == (
        settings.TRIVY_VERSION,
    )
