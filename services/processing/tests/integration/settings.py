import os
import pathlib

import rabbit

SERVICE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPO_DIR = SERVICE_DIR.parents[1]
MIGRATIONS_DIR = REPO_DIR / 'db'
BINARY = SERVICE_DIR / 'bin' / 'processing'

ADDR = os.environ.get('PROCESSING_TEST_ADDR', '127.0.0.1:18083')
PING_URL = f'http://{ADDR}/ping'

DATABASE = 'vulnmanager'
TENANT = 'acme'
SCOPE = (TENANT, 'payments', 'prod')
OTHER_SCOPE = (TENANT, 'billing', 'prod')

TOPOLOGY = rabbit.Topology(
    input_exchange='vulnmanager.import.completed',
    input_queue='vulnmanager.processing.import_completed',
)
RETRY_DELAY = '1s'

FINDINGS = 3
TRIVY_ALGO = 'tool-uid@1+identity@1'
SEMGREP_ALGO = 'tool-uid@1+structural@1'
FALLBACK_ALGO = 'tool-uid@1'
