from http import HTTPStatus

import pytest

import reports_client as rc
from reports_client import (
    FIRST_SCAN,
    SCAN_ID_HEADER,
    SCOPE_HEADER,
    SECOND_SCAN,
    TOOL_HEADER,
)
from settings import DATABASE


async def test_redelivery_returns_first_result(service_client, pgsql):
    first = await rc.post(service_client, add={SCAN_ID_HEADER: FIRST_SCAN})
    second = await rc.post(service_client, add={SCAN_ID_HEADER: SECOND_SCAN})

    assert second.status == HTTPStatus.ACCEPTED
    assert second.json() == first.json()
    assert rc.jobs(pgsql, DATABASE) == [('trivy', FIRST_SCAN, 'pending')]
    assert rc.blob_count(pgsql, DATABASE) == 1


@pytest.mark.parametrize(
    'different',
    [
        {TOOL_HEADER: 'semgrep'},
        {SCOPE_HEADER: 'payments/stage'},
        {SCOPE_HEADER: 'billing/prod'},
    ],
)
async def test_other_tool_or_scope_is_new_work(
    service_client, pgsql, different,
):
    await rc.post(service_client, add={SCAN_ID_HEADER: FIRST_SCAN})
    response = await rc.post(
        service_client, add={SCAN_ID_HEADER: SECOND_SCAN} | different,
    )

    assert response.status == HTTPStatus.ACCEPTED
    assert response.json()[rc.SCAN_ID_FIELD] == SECOND_SCAN
    assert len(rc.jobs(pgsql, DATABASE)) == 2
