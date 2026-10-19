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
async def service_daemon(create_daemon_scope, app_database_url, amqp_url):
    async with create_daemon_scope(
        args=[str(settings.BINARY)],
        env={
            'PROCESSING_ADDR': settings.ADDR,
            'PROCESSING_DATABASE_URL': app_database_url,
            'PROCESSING_AMQP_URL': amqp_url,
            'PROCESSING_RETRY_DELAY': settings.RETRY_DELAY,
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
