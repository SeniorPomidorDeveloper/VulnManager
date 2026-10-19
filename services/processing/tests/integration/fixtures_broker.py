import aio_pika
import pytest

import database
import rabbit
import seed
import settings


@pytest.fixture
async def broker(amqp_url, service_client):
    connection = await aio_pika.connect_robust(amqp_url)
    async with connection:
        yield await rabbit.open_broker(connection, settings.TOPOLOGY)


@pytest.fixture
def cursor(pgsql):
    return pgsql[settings.DATABASE].cursor()


@pytest.fixture
def db(cursor):
    return database.Database(cursor)


@pytest.fixture
def seeder(cursor):
    return seed.Seeder(cursor)
