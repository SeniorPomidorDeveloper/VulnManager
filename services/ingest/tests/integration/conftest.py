import os
import pathlib

import psycopg2
import pytest
import yaml
from jsonschema import Draft202012Validator
from testsuite.databases.pgsql import discover

pytest_plugins = [
    'testsuite.pytest_plugin',
    'testsuite.databases.pgsql.pytest_plugin',
]

SERVICE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPO_DIR = SERVICE_DIR.parents[1]
MIGRATIONS_DIR = REPO_DIR / 'migrations'
OPENAPI_PATH = REPO_DIR / 'api' / 'openapi' / 'ingest.yaml'
BINARY = SERVICE_DIR / 'bin' / 'ingest'

ADDR = os.environ.get('INGEST_TEST_ADDR', '127.0.0.1:18080')
BASE_URL = f'http://{ADDR}/'
TENANT = 'acme'
TENANT_LIMIT = 1000
APP_ROLE = 'ingest_app'


@pytest.fixture(scope='session')
def pgsql_local(pgsql_local_create):
    databases = discover.find_schemas(None, [MIGRATIONS_DIR])
    return pgsql_local_create(list(databases.values()))


@pytest.fixture(scope='session')
def app_database_url(pgsql_local, ensure_service_started, _pgsql_service_settings):
    ensure_service_started('postgresql', settings=_pgsql_service_settings)
    pgsql_local.initialize(parallel_init=False)
    conninfo = pgsql_local['ingest']
    conn = psycopg2.connect(conninfo.get_dsn())
    conn.autocommit = True
    conn.cursor().execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS;
            END IF;
        END
        $$;
        GRANT ALL ON ALL TABLES IN SCHEMA public TO {APP_ROLE};
        """,
    )
    conn.close()
    return conninfo.replace(user=APP_ROLE, password=None).get_uri()


@pytest.fixture(autouse=True)
def seeded_tenant(pgsql):
    pgsql['ingest'].cursor().execute(
        'INSERT INTO tenant (id, max_report_bytes) VALUES (%s, %s)',
        (TENANT, TENANT_LIMIT),
    )


@pytest.fixture(scope='session')
async def service_daemon(create_daemon_scope, app_database_url):
    async with create_daemon_scope(
        args=[str(BINARY)],
        env={
            'INGEST_ADDR': ADDR,
            'INGEST_DATABASE_URL': app_database_url,
            'INGEST_TENANT': TENANT,
            'INGEST_RAWSTORE': 'pg',
        },
        ping_url=BASE_URL + 'ping',
    ) as scope:
        yield scope


@pytest.fixture
async def service_client(ensure_daemon_started, create_service_client, service_daemon):
    await ensure_daemon_started(service_daemon)
    return create_service_client(BASE_URL)


@pytest.fixture(scope='session')
def openapi():
    return yaml.safe_load(OPENAPI_PATH.read_text(encoding='utf-8'))


@pytest.fixture
def assert_matches_spec(openapi):
    operation = openapi['paths']['/api/v1/reports']['post']

    def check(response, body):
        documented = operation['responses'].get(str(response.status))
        assert documented is not None, f'status {response.status} is not in the spec'
        content = documented.get('content')
        if content is None:
            content = openapi['components']['responses'][
                documented['$ref'].rsplit('/', 1)[1]
            ]['content']
        media_type = response.content_type
        assert media_type in content, f'content type {media_type} is not in the spec'
        schema = content[media_type]['schema']
        if '$ref' in schema:
            schema = openapi['components']['schemas'][schema['$ref'].rsplit('/', 1)[1]]
        Draft202012Validator(schema).validate(body)

    return check
