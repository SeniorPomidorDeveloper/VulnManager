import settings
import waiting
import wire_read
from submission import SEMGREP

PENDING = 'pending'
DONE = 'done'
DEAD = 'dead'
FAILED = 'failed'
GARBAGE = b'\xff\xff\xff'
JOB_ID_FIELD = 5


async def test_missing_object_is_retried(submit):
    submission = submit(settings.SEMGREP_REPORT.read_bytes(), SEMGREP)
    await submission.send()
    await waiting.until(
        lambda: submission.state() == PENDING and submission.attempts(),
    )

    submission.upload()

    await waiting.until(lambda: submission.state() == DONE)
    assert submission.findings() == settings.SEMGREP_FINDINGS


async def test_missing_object_ends_in_dead_letters(submit, broker):
    submission = submit(settings.SEMGREP_REPORT.read_bytes(), SEMGREP)
    await submission.send()

    await waiting.until(lambda: submission.state() == DEAD)
    message = await broker.get(await broker.queue(broker.topology.dead_queue))

    fields = wire_read.decode_fields(message.body)
    runs = submission.db.runs(submission.report.sha)
    assert fields[JOB_ID_FIELD].decode() == submission.report.job_id
    assert [status for _, status in runs] == [FAILED]
    assert submission.findings() == 0


async def test_undecodable_message_is_dead_lettered(broker):
    await broker.publish(GARBAGE, 'garbage')

    message = await broker.get(await broker.queue(broker.topology.dead_queue))

    assert message.body == GARBAGE
