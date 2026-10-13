import psycopg2
import pytest

import roles
import settings

SESSION = 'session'


@pytest.fixture(scope=SESSION)
def queue_dsn(app_database_url, pgsql_local):
    conninfo = pgsql_local[settings.DATABASE]
    return conninfo.replace(
        user=roles.QUEUE_CLIENT_ROLE, password=None,
    ).get_dsn()


@pytest.fixture
def consumer(queue_dsn):
    conn = psycopg2.connect(queue_dsn)
    conn.autocommit = True
    yield conn.cursor()
    conn.close()
