import hashlib
import types
from http import HTTPStatus

from reports_client import DEFAULT_SCOPE, job_ids, post
from settings import DATABASE, TENANT

SCHEMA = 'vulnmanager.ingest.v1.ReportReceived'
SCHEMA_VERSION = 1
HEADERS = types.MappingProxyType(
    {'schema': SCHEMA, 'schema_version': SCHEMA_VERSION},
)
TIMEOUT_SECONDS = 5


def scope_key():
    scope = f'{TENANT}/{DEFAULT_SCOPE}'
    return hashlib.sha256(scope.encode()).hexdigest()


async def test_accepted_report_is_published(
    service_client, event_queue, pgsql,
):
    response = await post(service_client)

    message = await event_queue.get(timeout=TIMEOUT_SECONDS)
    assert response.status == HTTPStatus.ACCEPTED
    assert message.message_id == job_ids(pgsql, DATABASE)[0]
    assert message.routing_key == scope_key()
    assert message.headers == HEADERS
    assert message.body


async def test_repeated_report_publishes_event_again(
    service_client, event_queue, pgsql,
):
    await post(service_client)
    await post(service_client)

    first = await event_queue.get(timeout=TIMEOUT_SECONDS)
    second = await event_queue.get(timeout=TIMEOUT_SECONDS)
    assert first.message_id == second.message_id
    assert len(job_ids(pgsql, DATABASE)) == 1
