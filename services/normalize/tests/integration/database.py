import ingest_jobs
import settings

SCAN_ID = 'scan-1'
FINDINGS = (
    'SELECT count(*) FROM finding f JOIN import_run r '
    'ON r.id = f.import_run_id AND r.tenant_id = f.tenant_id '
    'WHERE r.raw_sha256 = %s'
)
TITLES = (
    'SELECT DISTINCT f.title FROM finding f JOIN import_run r '
    'ON r.id = f.import_run_id AND r.tenant_id = f.tenant_id '
    'WHERE r.raw_sha256 = %s'
)
RUNS = 'SELECT id, status FROM import_run WHERE raw_sha256 = %s'
ATTEMPTS = 'SELECT attempts FROM ingest_job WHERE id = %s'


class Database:
    def __init__(self, cursor):
        self._cursor = cursor

    def insert_job(self, tool, sha256):
        return ingest_jobs.insert_report_job(
            self._cursor, settings.SCOPE, tool, SCAN_ID, sha256,
        )

    def job_state(self, job_id):
        return ingest_jobs.job_state(self._cursor, job_id)

    def attempts(self, job_id):
        self._cursor.execute(ATTEMPTS, (job_id,))
        return self._cursor.fetchone()[0]

    def findings(self, sha256):
        self._cursor.execute(FINDINGS, (sha256,))
        return self._cursor.fetchone()[0]

    def titles(self, sha256):
        self._cursor.execute(TITLES, (sha256,))
        return [row[0] for row in self._cursor.fetchall()]

    def runs(self, sha256):
        self._cursor.execute(RUNS, (sha256,))
        return [(str(run_id), status) for run_id, status in self._cursor]
