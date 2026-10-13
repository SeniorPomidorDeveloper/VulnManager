import os
import pathlib

INGEST_URL = os.environ.get('E2E_INGEST_URL', 'http://127.0.0.1:8080')
DATABASE_DSN = os.environ.get(
    'E2E_DATABASE_DSN',
    'host=127.0.0.1 dbname=vulnmanager user=vulnmanager '
    'password=vulnmanager-local-dev',
)
CORPUS = (
    pathlib.Path(__file__).resolve().parents[2]
    / 'testdata/corpus/trivy/0.75.0/juice-shop.json'
)
EXPECTED_FINDINGS = 69
WAIT_SECONDS = 60
POLL_SECONDS = 0.5
