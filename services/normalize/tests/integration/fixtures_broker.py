import functools

import aio_pika
import pytest

import database
import rabbit
import s3_mock
import settings
import submission


@pytest.fixture
def s3(mockserver):
    mock = s3_mock.S3Mock()
    mockserver.aiohttp_handler(
        f'/{settings.BUCKET}/', prefix=True, strict=False,
    )(mock.serve)
    return mock


@pytest.fixture
async def broker(amqp_url, service_client):
    connection = await aio_pika.connect_robust(amqp_url)
    async with connection:
        yield await rabbit.open_broker(connection, settings.TOPOLOGY)


@pytest.fixture
def db(pgsql):
    return database.Database(pgsql[settings.DATABASE].cursor())


@pytest.fixture
def submit(db, s3, broker):
    return functools.partial(submission.Submission, db, s3, broker)
