import client
import waiting

DELIVERED = (
    'SELECT 1 FROM import_run r JOIN processing_run p '
    'ON p.import_run_id = r.id AND p.tenant_id = r.tenant_id '
    'WHERE r.raw_sha256 = %s AND r.event_published_at IS NOT NULL'
)


def test_published_event_reaches_processing(database):
    _, answer = client.send(client.unique_trivy_report(), 'trivy')
    sha256 = client.completed(database, answer)

    assert waiting.until(
        lambda: client.fetch_one(database, DELIVERED, sha256),
    )
