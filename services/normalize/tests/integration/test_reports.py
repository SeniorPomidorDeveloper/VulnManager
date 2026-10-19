import functools

import metrics
import settings
import waiting
import wire_read
from submission import SEMGREP, TRIVY

DONE = 'done'
COMPLETED = 'completed'
UNPARSED = 'unparsed report'
UNKNOWN_TOOL = 'custom-scanner'
UNKNOWN_REPORT = b'{"scanner": "custom"}'
SCAN_ID = 'scan-1'


async def deliver(submission, service_client, acked):
    await submission.send()
    await waiting.until(
        functools.partial(metrics.acked_equals, service_client, acked),
    )


async def test_trivy_report_becomes_findings(submit, broker):
    submission = submit(settings.TRIVY_REPORT.read_bytes(), TRIVY)
    submission.upload()
    await submission.send()

    await waiting.until(lambda: submission.state() == DONE)
    event = await broker.get(broker.output)

    run_id, status = submission.db.runs(submission.report.sha)[0]
    assert status == COMPLETED
    assert submission.findings() == settings.TRIVY_FINDINGS
    assert wire_read.import_completed(event.body) == {
        'import_run_id': run_id,
        'scope': settings.SCOPE,
        'tool': TRIVY,
        'scan_id': SCAN_ID,
    }
    assert set(submission.s3.requested) == {submission.report.key}


async def test_semgrep_report_becomes_findings(submit, broker):
    submission = submit(settings.SEMGREP_REPORT.read_bytes(), SEMGREP)
    submission.upload()
    await submission.send()

    await waiting.until(lambda: submission.state() == DONE)
    event = await broker.get(broker.output)

    assert submission.findings() == settings.SEMGREP_FINDINGS
    assert wire_read.import_completed(event.body)['tool'] == SEMGREP


async def test_unknown_tool_is_kept_as_one_finding(submit):
    submission = submit(UNKNOWN_REPORT, UNKNOWN_TOOL)
    submission.upload()
    await submission.send()

    await waiting.until(lambda: submission.state() == DONE)

    assert submission.db.titles(submission.report.sha) == [UNPARSED]


async def test_redelivered_event_is_skipped(submit, broker, service_client):
    submission = submit(settings.SEMGREP_REPORT.read_bytes(), SEMGREP)
    acked = await metrics.acked_messages(service_client)
    submission.upload()

    await deliver(submission, service_client, acked + 1)
    await deliver(submission, service_client, acked + 2)

    await broker.get(broker.output)
    assert len(submission.db.runs(submission.report.sha)) == 1
    assert submission.findings() == settings.SEMGREP_FINDINGS
    assert set(submission.s3.requested) == {submission.report.key}
    assert await broker.output.get(fail=False) is None
