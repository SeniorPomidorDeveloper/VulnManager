import os
import pathlib

SERVICE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPO_DIR = SERVICE_DIR.parents[1]
MIGRATIONS_DIR = REPO_DIR / 'db'
OPENAPI_PATH = REPO_DIR / 'api' / 'openapi' / 'ingest.yaml'
BINARY = SERVICE_DIR / 'bin' / 'ingest'

ADDR = os.environ.get('INGEST_TEST_ADDR', '127.0.0.1:18080')
BASE_URL = f'http://{ADDR}/'
PING_URL = f'{BASE_URL}ping'

DATABASE = 'vulnmanager'
TENANT = 'acme'
TENANT_LIMIT = 1000
