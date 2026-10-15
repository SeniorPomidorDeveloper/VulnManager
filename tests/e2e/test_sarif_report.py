import client
import pytest
import settings

SEMGREP = 'semgrep'
RULES = (
    'SELECT count(*), count(f.rule_id) FROM finding f '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s'
)
VERSIONS = (
    "SELECT string_agg(DISTINCT f.provenance->>'tool_version', ',') "
    'FROM finding f JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s'
)
SNIPPETS = (
    'SELECT count(*), count(*) FILTER (WHERE f.location ? \'snippet\') '
    'FROM finding f JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s'
)


@pytest.fixture(scope='module')
def sarif_sha(database):
    _, answer = client.send(client.unique_sarif_report(), SEMGREP)
    return client.completed(database, answer)


def test_sarif_findings_keep_the_rule_id(database, sarif_sha):
    assert client.fetch_one(database, RULES, sarif_sha) == (
        settings.EXPECTED_SARIF_FINDINGS,
        settings.EXPECTED_SARIF_FINDINGS,
    )


def test_sarif_findings_keep_the_code_snippet(database, sarif_sha):
    assert client.fetch_one(database, SNIPPETS, sarif_sha) == (
        settings.EXPECTED_SARIF_FINDINGS,
        settings.EXPECTED_SARIF_FINDINGS,
    )


def test_sarif_findings_record_the_tool_version(database, sarif_sha):
    assert client.fetch_one(database, VERSIONS, sarif_sha) == (
        settings.SEMGREP_VERSION,
    )
