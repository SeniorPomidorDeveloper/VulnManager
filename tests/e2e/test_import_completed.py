import client
import pytest
import rabbit
import waiting

EXCHANGE = 'vulnmanager.import.completed'
QUEUE = 'e2e.import_completed'
RUN_ID = (
    'SELECT id::text FROM import_run '
    "WHERE raw_sha256 = %s AND status = 'completed'"
)
PUBLISHED = (
    'SELECT 1 FROM import_run '
    'WHERE raw_sha256 = %s AND event_published_at IS NOT NULL'
)


@pytest.fixture
def probe_queue():
    rabbit.bind(EXCHANGE, QUEUE)
    yield QUEUE
    rabbit.delete(QUEUE)


def test_event_carries_run_id_and_marks_run(database, probe_queue):
    _, answer = client.send(client.unique_trivy_report(), 'trivy')
    sha256 = client.completed(database, answer)
    run_id = client.fetch_one(database, RUN_ID, sha256)[0]

    message = waiting.until(lambda: rabbit.first_message(probe_queue))

    assert run_id.encode() in message
    waiting.until(lambda: client.fetch_one(database, PUBLISHED, sha256))
