import ingest_jobs
import queue_sql
import settings

OTHER_TENANT = 'globex'
RUNNING = 'running'
PENDING = 'pending'
EXPIRED = '0 seconds'


def test_claim_takes_the_job_of_any_tenant(pgsql, consumer):
    cursor = pgsql[settings.DATABASE].cursor()
    other = ingest_jobs.insert_job(cursor, OTHER_TENANT)

    claimed = queue_sql.claim(consumer, other)

    assert claimed[:2] == (other, OTHER_TENANT)


def test_live_lease_is_not_taken_over(consumer, job_id):
    queue_sql.claim(consumer, job_id)

    assert queue_sql.claim(consumer, job_id, worker='w2') is None
    assert queue_sql.state(consumer, job_id) == (RUNNING,)


def test_expired_lease_is_claimed_again(consumer, job_id):
    queue_sql.claim(consumer, job_id, lease=EXPIRED)

    row = queue_sql.claim(consumer, job_id, worker='w2')

    assert row[-1] == 2


def test_only_the_lock_owner_can_finish(consumer, job_id):
    queue_sql.claim(consumer, job_id)

    assert queue_sql.finish(consumer, job_id, 'done', worker='w2') == 0
    assert queue_sql.finish(consumer, job_id, 'done') == 1
    assert queue_sql.claim(consumer, job_id) is None
    assert queue_sql.state(consumer, job_id) == ('done',)


def test_retried_job_is_claimed_without_waiting(consumer, job_id):
    queue_sql.claim(consumer, job_id)
    queue_sql.finish(consumer, job_id, PENDING)

    row = queue_sql.claim(consumer, job_id)

    assert row[-1] == 2


def test_unknown_job_has_no_state(consumer):
    unknown = '00000000-0000-0000-0000-000000000000'

    assert queue_sql.state(consumer, unknown) is None
