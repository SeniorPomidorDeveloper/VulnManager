import pytest
from testsuite.databases.pgsql import discover

import finding_sql
import ingest_jobs
import settings

pytest_plugins = [
    'testsuite.pytest_plugin',
    'testsuite.databases.pgsql.pytest_plugin',
    'testsuite.databases.rabbitmq.pytest_plugin',
    'fixtures_rabbit',
    'fixtures_service',
    'fixtures_broker',
]
SESSION = 'session'


@pytest.fixture(scope=SESSION)
def pgsql_local(pgsql_local_create):
    databases = discover.find_schemas(None, [settings.MIGRATIONS_DIR])
    return pgsql_local_create([databases[settings.DATABASE]])


@pytest.fixture
def consumer(pgsql):
    return pgsql[settings.DATABASE].cursor()


@pytest.fixture
def job_id(pgsql):
    cursor = pgsql[settings.DATABASE].cursor()
    return ingest_jobs.insert_job(cursor, settings.TENANT)


@pytest.fixture
def cursor(pgsql):
    return pgsql[settings.DATABASE].cursor()


@pytest.fixture
def run_id(cursor):
    cursor.execute(finding_sql.INSERT_RUN, ('completed',))
    return cursor.fetchone()[0]
