import os
import pathlib

import rabbit

SERVICE_DIR = pathlib.Path(__file__).resolve().parents[2]
REPO_DIR = SERVICE_DIR.parents[1]
MIGRATIONS_DIR = REPO_DIR / 'db'
CORPUS_DIR = REPO_DIR / 'testdata' / 'corpus'
BINARY = SERVICE_DIR / 'bin' / 'normalize'

ADDR = os.environ.get('NORMALIZE_TEST_ADDR', '127.0.0.1:18082')
PING_URL = f'http://{ADDR}/ping'

DATABASE = 'vulnmanager'
TENANT = 'acme'
SCOPE = (TENANT, 'payments', 'prod')

BUCKET = 'raw'
S3_ACCESS_KEY = 'access'
S3_SECRET_KEY = 'secret'

TOPOLOGY = rabbit.Topology(
    input_exchange='vulnmanager.report.received',
    input_queue='vulnmanager.normalize.report_received',
    output_exchange='vulnmanager.import.completed',
)
RETRY_DELAY = '1s'
MAX_ATTEMPTS = '3'

TRIVY_REPORT = CORPUS_DIR / 'trivy' / '0.75.0' / 'juice-shop.json'
SEMGREP_REPORT = CORPUS_DIR / 'semgrep' / '1.180.0' / 'juice-shop.sarif'
TRIVY_FINDINGS = 69
SEMGREP_FINDINGS = 33
WAIT_SECONDS = 20
