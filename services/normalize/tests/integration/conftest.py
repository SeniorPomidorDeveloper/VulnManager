import pytest
from testsuite.databases.pgsql import discover

import settings

pytest_plugins = [
    'testsuite.pytest_plugin',
    'testsuite.databases.pgsql.pytest_plugin',
]


@pytest.fixture(scope='session')
def pgsql_local(pgsql_local_create):
    databases = discover.find_schemas(None, [settings.MIGRATIONS_DIR])
    return pgsql_local_create([databases[settings.DATABASE]])
