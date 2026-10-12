from http import HTTPStatus

import pytest

from reports_client import SCOPE_HEADER, TOOL_HEADER, jobs, post
from settings import DATABASE


@pytest.mark.parametrize(
    ('add', 'drop'),
    [
        ({}, (TOOL_HEADER,)),
        ({}, (SCOPE_HEADER,)),
        ({SCOPE_HEADER: '/context-only'}, ()),
    ],
)
async def test_invalid_headers_are_rejected(
    service_client, pgsql, assert_matches_spec, add, drop,
):
    response = await post(service_client, add=add, drop=drop)

    assert response.status == HTTPStatus.BAD_REQUEST
    assert_matches_spec(response, response.json())
    assert jobs(pgsql, DATABASE) == []


async def test_empty_body_is_rejected(
    service_client, pgsql, assert_matches_spec,
):
    response = await post(service_client, body=b'')

    assert response.status == HTTPStatus.BAD_REQUEST
    assert_matches_spec(response, response.json())
    assert jobs(pgsql, DATABASE) == []
