import client
import settings

MEMBERS = (
    'SELECT count(*) FROM cluster_member m '
    'JOIN finding f ON f.id = m.finding_id AND f.tenant_id = m.tenant_id '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s'
)
JOINED = (
    'SELECT count(*) FROM cluster_member m '
    'JOIN finding f ON f.id = m.finding_id AND f.tenant_id = m.tenant_id '
    'JOIN import_run r ON r.id = f.import_run_id '
    'AND r.tenant_id = f.tenant_id WHERE r.raw_sha256 = %s '
    'AND EXISTS (SELECT 1 FROM cluster_member o '
    'JOIN finding g ON g.id = o.finding_id AND g.tenant_id = o.tenant_id '
    'JOIN import_run q ON q.id = g.import_run_id '
    'AND q.tenant_id = g.tenant_id WHERE o.cluster_id = m.cluster_id '
    'AND q.raw_sha256 = %s)'
)


def import_twice(database, report, tool):
    shas = []
    for _ in range(2):
        _, answer = client.send(report(), tool)
        sha256 = client.completed(database, answer)
        client.processed(database, sha256)
        shas.append(sha256)
    return shas


def joined(database, first, second):
    with database.cursor() as cursor:
        cursor.execute(JOINED, (second, first))
        return cursor.fetchone()[0]


def test_repeated_trivy_report_joins_clusters(database):
    first, second = import_twice(
        database, client.unique_trivy_report, 'trivy',
    )

    assert client.fetch_one(database, MEMBERS, second) == (
        settings.EXPECTED_FINDINGS,
    )
    assert joined(database, first, second) == settings.EXPECTED_FINDINGS


def test_repeated_semgrep_report_joins_clusters(database):
    first, second = import_twice(
        database, client.unique_sarif_report, 'semgrep',
    )

    assert client.fetch_one(database, MEMBERS, second) == (
        settings.EXPECTED_SARIF_FINDINGS,
    )
    assert joined(
        database, first, second,
    ) == settings.EXPECTED_SARIF_FINDINGS
