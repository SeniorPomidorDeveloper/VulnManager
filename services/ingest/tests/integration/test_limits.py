from http import HTTPStatus

from reports_client import blob_count, jobs, post
from settings import DATABASE, TENANT_LIMIT


async def test_report_above_limit_is_rejected(
    service_client, pgsql, assert_matches_spec,
):
    response = await post(service_client, body=b'a' * (TENANT_LIMIT + 1))

    assert response.status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    assert_matches_spec(response, response.json())
    assert jobs(pgsql, DATABASE) == []
    assert blob_count(pgsql, DATABASE) == 0


async def test_report_at_limit_is_accepted(service_client):
    response = await post(service_client, body=b'a' * TENANT_LIMIT)

    assert response.status == HTTPStatus.ACCEPTED
