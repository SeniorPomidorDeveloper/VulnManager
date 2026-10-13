import json
from urllib import request
import uuid

import settings
import waiting

ACCEPTED = 202
COMPLETED_RUN = (
    'SELECT id FROM import_run '
    "WHERE raw_sha256 = %s AND status = 'completed'"
)
FINDINGS = (
    'SELECT count(*) FROM finding f JOIN import_run r '
    'ON r.id = f.import_run_id AND r.tenant_id = f.tenant_id '
    'WHERE r.raw_sha256 = %s'
)


def unique_report():
    report = json.loads(settings.CORPUS.read_text())
    report['ReportID'] = str(uuid.uuid4())
    return json.dumps(report).encode()


def send(body):
    upload = request.Request(
        f'{settings.INGEST_URL}/api/v1/reports',
        data=body,
        headers={'X-Tool': 'trivy', 'X-Scope': 'e2e/main'},
    )
    with request.urlopen(upload) as response:
        return response.status, json.load(response)


def fetch_one(database, query, sha256):
    with database.cursor() as cursor:
        cursor.execute(query, (sha256,))
        return cursor.fetchone()


def test_trivy_report_becomes_findings(database):
    status, answer = send(unique_report())
    assert status == ACCEPTED

    sha256 = answer['sha256']
    waiting.until(lambda: fetch_one(database, COMPLETED_RUN, sha256))
    assert fetch_one(database, FINDINGS, sha256) == (
        settings.EXPECTED_FINDINGS,
    )
