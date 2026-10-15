import client
import pytest
import settings
import waiting

PROCESSED = (
    'SELECT p.algo_version FROM processing_run p '
    'JOIN import_run r ON r.id = p.import_run_id '
    'AND r.tenant_id = p.tenant_id WHERE r.raw_sha256 = %s'
)
LEVELS = (
    'SELECT ff.level, count(*) FROM finding_fingerprint ff '
    'JOIN finding f ON f.id = ff.finding_id AND f.tenant_id = ff.tenant_id '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s '
    'GROUP BY ff.level ORDER BY ff.level'
)
VERSIONS = (
    'SELECT DISTINCT ff.strategy, ff.version, '
    "ff.value LIKE 'v' || ff.version || ':' || ff.level || ':sha256:%%' "
    'FROM finding_fingerprint ff '
    'JOIN finding f ON f.id = ff.finding_id AND f.tenant_id = ff.tenant_id '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s '
    'ORDER BY ff.strategy'
)


@pytest.fixture(scope='module')
def trivy_sha(database):
    _, answer = client.send(client.unique_trivy_report(), 'trivy')
    return client.completed(database, answer)


@pytest.fixture(scope='module')
def sarif_sha(database):
    _, answer = client.send(client.unique_sarif_report(), 'semgrep')
    return client.completed(database, answer)


def processed(database, sha256):
    return waiting.until(
        lambda: client.fetch_one(database, PROCESSED, sha256),
    )


def test_trivy_run_gets_identity_fingerprints(database, trivy_sha):
    assert processed(database, trivy_sha) == (settings.TRIVY_ALGO,)
    assert client.fetch_all(database, LEVELS, trivy_sha) == [
        ('l0', settings.EXPECTED_FINDINGS),
        ('l1', settings.EXPECTED_FINDINGS),
    ]


def test_semgrep_run_gets_structural_fingerprints(database, sarif_sha):
    assert processed(database, sarif_sha) == (settings.SEMGREP_ALGO,)
    assert client.fetch_all(database, LEVELS, sarif_sha) == [
        ('l0', settings.EXPECTED_SARIF_FINDINGS),
        ('l2', settings.EXPECTED_SARIF_FINDINGS),
    ]


def test_value_carries_strategy_version(database, trivy_sha):
    processed(database, trivy_sha)

    assert client.fetch_all(database, VERSIONS, trivy_sha) == [
        ('identity', 1, True),
        ('tool-uid', 1, True),
    ]
