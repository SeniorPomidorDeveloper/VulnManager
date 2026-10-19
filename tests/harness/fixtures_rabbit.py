import os
import pathlib

import pytest

SESSION = 'session'
ENABLED_PLUGINS = pathlib.Path(__file__).resolve().parent / 'enabled_plugins'

os.environ['RABBITMQ_ENABLED_PLUGINS_FILE'] = str(ENABLED_PLUGINS)


@pytest.fixture(scope=SESSION)
def amqp_url(_rabbitmq_service, _rabbitmq_service_settings):
    broker = _rabbitmq_service_settings.get_connection_info()
    return f'amqp://guest:guest@{broker.host}:{broker.tcp_port}/'
