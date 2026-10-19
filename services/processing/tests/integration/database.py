ALGO_VERSION = (
    'SELECT algo_version FROM processing_run WHERE import_run_id = %s'
)
LEVELS = (
    'SELECT ff.level, count(*) FROM finding_fingerprint ff '
    'JOIN finding f ON f.id = ff.finding_id AND f.tenant_id = ff.tenant_id '
    'WHERE f.import_run_id = %s GROUP BY ff.level ORDER BY ff.level'
)
MEMBERS = (
    'SELECT count(*) FROM cluster_member m '
    'JOIN finding f ON f.id = m.finding_id AND f.tenant_id = m.tenant_id '
    'WHERE f.import_run_id = %s'
)
JOINED = (
    'SELECT count(*) FROM cluster_member m '
    'JOIN finding f ON f.id = m.finding_id AND f.tenant_id = m.tenant_id '
    'WHERE f.import_run_id = %s AND EXISTS ('
    'SELECT 1 FROM cluster_member o '
    'JOIN finding g ON g.id = o.finding_id AND g.tenant_id = o.tenant_id '
    'WHERE o.cluster_id = m.cluster_id AND g.import_run_id = %s)'
)
PROCESSED_RUNS = 'SELECT count(*) FROM processing_run'
CLUSTERS = 'SELECT count(*) FROM cluster'


def _fetch_one(cursor, query, *args):
    cursor.execute(query, args)
    return cursor.fetchone()


class Database:
    def __init__(self, cursor):
        self._cursor = cursor

    def algo_version(self, run_id):
        row = _fetch_one(self._cursor, ALGO_VERSION, run_id)
        return row[0] if row else None

    def levels(self, run_id):
        self._cursor.execute(LEVELS, (run_id,))
        return tuple(self._cursor.fetchall())

    def members(self, run_id):
        return _fetch_one(self._cursor, MEMBERS, run_id)[0]

    def joined(self, run_id, other_run_id):
        return _fetch_one(self._cursor, JOINED, run_id, other_run_id)[0]

    def processed_runs(self):
        return _fetch_one(self._cursor, PROCESSED_RUNS)[0]

    def clusters(self):
        return _fetch_one(self._cursor, CLUSTERS)[0]
