import pytest

import settings

SESSION = 'session'


@pytest.fixture(scope=SESSION)
def app_database_url(
    pgsql_local, ensure_service_started, _pgsql_service_settings,
):
    ensure_service_started('postgresql', settings=_pgsql_service_settings)
    pgsql_local.initialize(parallel_init=False)
    return pgsql_local[settings.DATABASE].get_uri()


@pytest.fixture(scope=SESSION)
async def service_daemon(
    create_daemon_scope, app_database_url, amqp_url, mockserver_info,
):
    async with create_daemon_scope(
        args=[str(settings.BINARY)],
        env={
            'NORMALIZE_ADDR': settings.ADDR,
            'NORMALIZE_DATABASE_URL': app_database_url,
            'NORMALIZE_S3_ENDPOINT': (
                f'{mockserver_info.host}:{mockserver_info.port}'
            ),
            'NORMALIZE_S3_ACCESS_KEY': settings.S3_ACCESS_KEY,
            'NORMALIZE_S3_SECRET_KEY': settings.S3_SECRET_KEY,
            'NORMALIZE_S3_BUCKET': settings.BUCKET,
            'NORMALIZE_S3_SSL': 'false',
            'NORMALIZE_AMQP_URL': amqp_url,
            'NORMALIZE_RETRY_DELAY': settings.RETRY_DELAY,
            'NORMALIZE_MAX_ATTEMPTS': settings.MAX_ATTEMPTS,
        },
        ping_url=settings.PING_URL,
    ) as scope:
        yield scope


@pytest.fixture
async def service_client(
    ensure_daemon_started, create_service_client, service_daemon,
):
    await ensure_daemon_started(service_daemon)
    return create_service_client(f'http://{settings.ADDR}/')
