import pytest
from testsuite.databases.pgsql import discover

import ingest_jobs
import roles
import settings

pytest_plugins = [
    'testsuite.pytest_plugin',
    'testsuite.databases.pgsql.pytest_plugin',
]


@pytest.fixture(scope='session')
def pgsql_local(pgsql_local_create):
    databases = discover.find_schemas(None, [settings.MIGRATIONS_DIR])
    return pgsql_local_create([databases[settings.DATABASE]])


@pytest.fixture(scope='session', autouse=True)
def cluster_roles(
    pgsql_local, ensure_service_started, _pgsql_service_settings,
):
    ensure_service_started('postgresql', settings=_pgsql_service_settings)
    conninfo = pgsql_local[settings.DATABASE]
    roles.create_cluster_roles(conninfo.replace(dbname='postgres'))


@pytest.fixture
def consumer(pgsql):
    return pgsql[settings.DATABASE].cursor()


@pytest.fixture
def job_id(pgsql):
    cursor = pgsql[settings.DATABASE].cursor()
    return ingest_jobs.insert_job(cursor, settings.TENANT)
