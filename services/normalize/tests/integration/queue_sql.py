import re

import settings

QUERIES_DIR = settings.SERVICE_DIR / 'queries'
NAMED = re.compile(r'@(\w+)')


def load(name):
    text = (QUERIES_DIR / f'{name}.sql').read_text(encoding='utf-8')
    body = text.split('\n', 1)[1]
    return NAMED.sub(r'%(\1)s', body).replace('$1', '%(id)s')


def claim(cursor, job_id, worker='w1', lease='1 hour'):
    cursor.execute(
        load('claim_ingest_job'),
        {'id': job_id, 'worker': worker, 'lease': lease},
    )
    return cursor.fetchone()


def finish(cursor, job_id, state, worker='w1'):
    cursor.execute(
        load('finish_ingest_job'),
        {'id': job_id, 'worker': worker, 'state': state},
    )
    return cursor.rowcount


def state(cursor, job_id):
    cursor.execute(load('get_ingest_job_state'), {'id': job_id})
    return cursor.fetchone()
