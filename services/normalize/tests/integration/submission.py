import hashlib
import typing

import database
import settings
import wire

TRIVY = 'trivy'
SEMGREP = 'semgrep'


class Report(typing.NamedTuple):
    body: bytes
    tool: str
    sha: str
    key: str
    job_id: str


class Submission:
    def __init__(self, db, s3, broker, body, tool=TRIVY):
        self.db = db
        self.s3 = s3
        self.broker = broker
        sha = hashlib.sha256(body).hexdigest()
        key = f'{settings.TENANT}/{database.SCAN_ID}/{sha}'
        self.report = Report(body, tool, sha, key, db.insert_job(tool, sha))

    def upload(self):
        self.s3.put(self.report.key, self.report.body)

    async def send(self):
        payload = wire.report_received(
            self.report.job_id,
            self.report.key,
            settings.SCOPE,
            self.report.tool,
            database.SCAN_ID,
        )
        await self.broker.publish(payload, self.report.job_id)

    def state(self):
        return self.db.job_state(self.report.job_id)

    def attempts(self):
        return self.db.attempts(self.report.job_id)

    def findings(self):
        return self.db.findings(self.report.sha)
