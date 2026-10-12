import pytest

REPORTS = '/api/v1/reports'


def headers(**overrides):
    base = {
        'X-Tool': 'trivy',
        'X-Scope': 'payments/prod',
        'X-Scan-Id': 'scan-1',
    }
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not None}


async def post(client, body=b'report', **overrides):
    return await client.post(REPORTS, headers=headers(**overrides), data=body)


def jobs(pgsql):
    cursor = pgsql['ingest'].cursor()
    cursor.execute(
        'SELECT tool, scan_id, state FROM ingest_job '
        'ORDER BY created_at, tool',
    )
    return cursor.fetchall()


def blob_count(pgsql):
    cursor = pgsql['ingest'].cursor()
    cursor.execute('SELECT count(*) FROM raw_blob')
    return cursor.fetchone()[0]


async def test_report_is_accepted(service_client, pgsql, assert_matches_spec):
    response = await post(service_client)

    body = response.json()
    assert response.status == 202
    assert_matches_spec(response, body)
    assert body['scan_id'] == 'scan-1'
    assert jobs(pgsql) == [('trivy', 'scan-1', 'pending')]
    assert blob_count(pgsql) == 1


async def test_server_assigns_scan_id(service_client, pgsql):
    response = await post(service_client, **{'X-Scan-Id': None})

    body = response.json()
    assert response.status == 202
    assert body['scan_id']
    assert jobs(pgsql) == [('trivy', body['scan_id'], 'pending')]


async def test_redelivery_returns_first_result_without_new_work(
    service_client, pgsql,
):
    first = await post(service_client, **{'X-Scan-Id': 'scan-1'})
    second = await post(service_client, **{'X-Scan-Id': 'scan-2'})

    assert second.status == 202
    assert second.json() == first.json()
    assert jobs(pgsql) == [('trivy', 'scan-1', 'pending')]
    assert blob_count(pgsql) == 1


@pytest.mark.parametrize(
    'overrides',
    [
        {'X-Tool': 'semgrep'},
        {'X-Scope': 'payments/stage'},
        {'X-Scope': 'billing/prod'},
    ],
)
async def test_other_tool_or_scope_is_not_a_duplicate(
    service_client, pgsql, overrides,
):
    await post(service_client, **{'X-Scan-Id': 'scan-1'})
    response = await post(
        service_client, **{'X-Scan-Id': 'scan-2', **overrides},
    )

    assert response.status == 202
    assert (response.json())['scan_id'] == 'scan-2'
    assert len(jobs(pgsql)) == 2


async def test_report_above_tenant_limit_is_rejected(
    service_client, pgsql, assert_matches_spec,
):
    response = await post(service_client, body=b'a' * 1001)

    assert response.status == 413
    assert_matches_spec(response, response.json())
    assert jobs(pgsql) == []
    assert blob_count(pgsql) == 0


async def test_report_at_tenant_limit_is_accepted(service_client):
    response = await post(service_client, body=b'a' * 1000)

    assert response.status == 202


@pytest.mark.parametrize(
    'overrides',
    [{'X-Tool': None}, {'X-Scope': None}, {'X-Scope': '/context-only'}],
)
async def test_invalid_headers_are_rejected(
    service_client, pgsql, assert_matches_spec, overrides,
):
    response = await post(service_client, **overrides)

    assert response.status == 400
    assert_matches_spec(response, response.json())
    assert jobs(pgsql) == []


async def test_empty_body_is_rejected(
    service_client, pgsql, assert_matches_spec,
):
    response = await post(service_client, body=b'')

    assert response.status == 400
    assert_matches_spec(response, response.json())
    assert jobs(pgsql) == []
