import settings

LEASE = '1 hour'
EXPIRED = '0 seconds'
WORKER = 'worker-1'
OTHER_WORKER = 'worker-2'
OTHER_TENANT = 'globex'


def insert_job(pgsql, tenant=settings.TENANT, tool='trivy'):
    cursor = pgsql[settings.DATABASE].cursor()
    cursor.execute(
        'INSERT INTO ingest_job (tenant_id, scope_key, product_id, '
        'context_id, raw_key, tool, sha256, scan_id) '
        "VALUES (%s, 'scope', 'payments', 'prod', 'key', %s, %s, 'scan-1') "
        'RETURNING id',
        (tenant, tool, f'sha-{tenant}-{tool}'),
    )
    return cursor.fetchone()[0]


def claim(cursor, worker=WORKER, lease=LEASE):
    cursor.execute(
        'SELECT id, tenant_id, product_id, context_id, tool, attempts '
        'FROM claim_ingest_job(%s, %s::interval)',
        (worker, lease),
    )
    return cursor.fetchone()


def finish(
    cursor, job_id, worker=WORKER, state='done', retry_after='0 seconds',
):
    cursor.execute(
        'SELECT finish_ingest_job(%s, %s, %s, %s::interval)',
        (job_id, worker, state, retry_after),
    )
    return cursor.fetchone()[0]


def job_state(pgsql, job_id):
    cursor = pgsql[settings.DATABASE].cursor()
    cursor.execute('SELECT state FROM ingest_job WHERE id = %s', (job_id,))
    return cursor.fetchone()[0]
