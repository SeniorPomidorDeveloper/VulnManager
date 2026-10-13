import psycopg2
import pytest

import settings


@pytest.fixture(scope='session')
def database():
    connection = psycopg2.connect(settings.DATABASE_DSN)
    connection.autocommit = True
    yield connection
    connection.close()
