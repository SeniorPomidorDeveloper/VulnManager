import json
import uuid
from urllib import request

import settings
import waiting

PROCESSED = (
    'SELECT p.algo_version FROM processing_run p '
    'JOIN import_run r ON r.id = p.import_run_id '
    'AND r.tenant_id = p.tenant_id WHERE r.raw_sha256 = %s'
)
COMPLETED_RUN = (
    'SELECT id FROM import_run '
    "WHERE raw_sha256 = %s AND status = 'completed'"
)


def send(body, tool):
    upload = request.Request(
        f'{settings.INGEST_URL}/api/v1/reports',
        data=body,
        headers={'X-Tool': tool, 'X-Scope': 'e2e/main'},
    )
    with request.urlopen(upload) as response:
        return response.status, json.load(response)


def fetch_one(database, query, sha256):
    with database.cursor() as cursor:
        cursor.execute(query, (sha256,))
        return cursor.fetchone()


def fetch_all(database, query, sha256):
    with database.cursor() as cursor:
        cursor.execute(query, (sha256,))
        return cursor.fetchall()


def completed(database, answer):
    sha256 = answer['sha256']
    waiting.until(lambda: fetch_one(database, COMPLETED_RUN, sha256))
    return sha256


def processed(database, sha256):
    return waiting.until(
        lambda: fetch_one(database, PROCESSED, sha256),
    )


def unique_trivy_report():
    report = json.loads(settings.CORPUS.read_text())
    report['ReportID'] = str(uuid.uuid4())
    return json.dumps(report).encode()


def unique_sarif_report():
    report = json.loads(settings.SARIF_CORPUS.read_text())
    report['properties'] = {'e2e': str(uuid.uuid4())}
    return json.dumps(report).encode()
