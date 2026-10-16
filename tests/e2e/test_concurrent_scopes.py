import json
import random
import uuid
from concurrent.futures import ThreadPoolExecutor

import client
import settings
import waiting

REPORTS = 16
BEFORE_RETRY_SECONDS = 40
COMPLETED = (
    'SELECT count(*) FROM import_run '
    "WHERE raw_sha256 = ANY(%s) AND status = 'completed'"
)


def shuffled_report(seed):
    report = json.loads(settings.CORPUS.read_text())
    random.Random(seed).shuffle(report['Results'][0]['Vulnerabilities'])
    report['ReportID'] = str(uuid.uuid4())
    return json.dumps(report).encode()


def send(seed):
    _, answer = client.send(
        shuffled_report(seed), 'trivy', f'e2e/concurrent-{seed}',
    )
    return answer['sha256']


def completed(database, shas):
    with database.cursor() as cursor:
        cursor.execute(COMPLETED, (shas,))
        return cursor.fetchone()[0] == len(shas)


def test_shared_components_do_not_deadlock(database):
    with ThreadPoolExecutor(REPORTS) as pool:
        shas = list(pool.map(send, range(REPORTS)))

    waiting.until(
        lambda: completed(database, shas),
        timeout=BEFORE_RETRY_SECONDS,
    )
