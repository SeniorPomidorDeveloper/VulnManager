INSERT_JOB = (
    'INSERT INTO ingest_job (tenant_id, scope_key, product_id, '
    'context_id, raw_key, tool, sha256, scan_id) '
    "VALUES (%s, 'scope', 'payments', 'prod', 'key', %s, %s, 'scan-1') "
    'RETURNING id'
)
SELECT_STATE = 'SELECT state FROM ingest_job WHERE id = %s'


def insert_job(cursor, tenant, tool='trivy'):
    cursor.execute(INSERT_JOB, (tenant, tool, f'sha-{tenant}-{tool}'))
    return cursor.fetchone()[0]


def job_state(cursor, job_id):
    cursor.execute(SELECT_STATE, (job_id,))
    return cursor.fetchone()[0]
