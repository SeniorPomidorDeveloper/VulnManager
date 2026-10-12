from http import HTTPStatus

from reports_client import (
    FIRST_SCAN,
    SCAN_ID_FIELD,
    SCAN_ID_HEADER,
    post,
    blob_count,
    jobs,
)
from settings import DATABASE


async def test_report_is_accepted(service_client, pgsql, assert_matches_spec):
    response = await post(service_client)

    body = response.json()
    assert response.status == HTTPStatus.ACCEPTED
    assert_matches_spec(response, body)
    assert body[SCAN_ID_FIELD] == FIRST_SCAN
    assert jobs(pgsql, DATABASE) == [('trivy', FIRST_SCAN, 'pending')]
    assert blob_count(pgsql, DATABASE) == 1


async def test_server_assigns_scan_id(service_client, pgsql):
    response = await post(service_client, drop=(SCAN_ID_HEADER,))

    body = response.json()
    assert response.status == HTTPStatus.ACCEPTED
    assert body[SCAN_ID_FIELD]
    assert jobs(pgsql, DATABASE) == [('trivy', body[SCAN_ID_FIELD], 'pending')]
