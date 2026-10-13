import functools

import pytest
import yaml
from testsuite.databases.pgsql import discover

import settings
import spec_check

pytest_plugins = [
    'testsuite.pytest_plugin',
    'testsuite.databases.pgsql.pytest_plugin',
]

SESSION = 'session'


@pytest.fixture(scope=SESSION)
def pgsql_local(pgsql_local_create):
    databases = discover.find_schemas(None, [settings.MIGRATIONS_DIR])
    return pgsql_local_create([databases[settings.DATABASE]])


@pytest.fixture(scope=SESSION)
def app_database_url(
    pgsql_local, ensure_service_started, _pgsql_service_settings,
):
    ensure_service_started('postgresql', settings=_pgsql_service_settings)
    pgsql_local.initialize(parallel_init=False)
    return pgsql_local[settings.DATABASE].get_uri()


@pytest.fixture(autouse=True)
def seeded_tenant(pgsql):
    pgsql[settings.DATABASE].cursor().execute(
        'INSERT INTO tenant (id, max_report_bytes) VALUES (%s, %s)',
        (settings.TENANT, settings.TENANT_LIMIT),
    )


@pytest.fixture(scope=SESSION)
async def service_daemon(create_daemon_scope, app_database_url):
    async with create_daemon_scope(
        args=[str(settings.BINARY)],
        env={
            'INGEST_ADDR': settings.ADDR,
            'INGEST_DATABASE_URL': app_database_url,
            'INGEST_TENANT': settings.TENANT,
            'INGEST_RAWSTORE': 'pg',
        },
        ping_url=settings.PING_URL,
    ) as scope:
        yield scope


@pytest.fixture
async def service_client(
    ensure_daemon_started, create_service_client, service_daemon,
):
    await ensure_daemon_started(service_daemon)
    return create_service_client(settings.BASE_URL)


@pytest.fixture(scope=SESSION)
def openapi():
    return yaml.safe_load(
        settings.OPENAPI_PATH.read_text(encoding='utf-8'),
    )


@pytest.fixture
def assert_matches_spec(openapi):
    return functools.partial(spec_check.matches_spec, openapi)
