import types

from spec_check import REPORTS_PATH

TOOL_HEADER = 'X-Tool'
SCOPE_HEADER = 'X-Scope'
SCAN_ID_HEADER = 'X-Scan-Id'

DEFAULT_TOOL = 'trivy'
DEFAULT_SCOPE = 'payments/prod'
FIRST_SCAN = 'scan-1'
SECOND_SCAN = 'scan-2'
SCAN_ID_FIELD = 'scan_id'

DEFAULT_HEADERS = types.MappingProxyType({
    TOOL_HEADER: DEFAULT_TOOL,
    SCOPE_HEADER: DEFAULT_SCOPE,
    SCAN_ID_HEADER: FIRST_SCAN,
})


async def post(client, body=b'report', add=None, drop=()):
    merged = DEFAULT_HEADERS | (add or {})
    headers = {
        name: header
        for name, header in merged.items()
        if name not in drop
    }
    return await client.post(REPORTS_PATH, headers=headers, data=body)


def jobs(pgsql, database):
    cursor = pgsql[database].cursor()
    cursor.execute(
        'SELECT tool, scan_id, state FROM ingest_job '
        'ORDER BY created_at, tool',
    )
    return cursor.fetchall()


def blob_count(pgsql, database):
    cursor = pgsql[database].cursor()
    cursor.execute('SELECT count(*) FROM raw_blob')
    return cursor.fetchone()[0]
