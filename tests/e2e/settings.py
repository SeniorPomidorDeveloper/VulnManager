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
SARIF_CORPUS = (
    pathlib.Path(__file__).resolve().parents[2]
    / 'testdata/corpus/semgrep/1.180.0/juice-shop.sarif'
)
EXPECTED_SARIF_FINDINGS = 33
EXPECTED_CWE_ROWS = 86
EXPECTED_CWE_FINDINGS = 59
TRIVY_VERSION = '0.75.0'
SEMGREP_VERSION = '1.180.0'
EXPECTED_FINDINGS = 69
EXPECTED_COMPONENTS = 25
EXPECTED_CVSS_ROWS = 177
EXPECTED_CVSS_FINDINGS = 63
TRIVY_ALGO = 'tool-uid@1+identity@1'
SEMGREP_ALGO = 'tool-uid@1+structural@1'
WAIT_SECONDS = 60
POLL_SECONDS = 0.5
