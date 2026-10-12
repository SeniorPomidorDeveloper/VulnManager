import queue_client as queue


def test_only_the_lock_owner_can_finish(pgsql, consumer):
    job_id = queue.insert_job(pgsql)
    queue.claim(consumer)

    assert queue.finish(consumer, job_id, worker=queue.OTHER_WORKER) is False
    assert queue.finish(consumer, job_id) is True
    assert queue.job_state(pgsql, job_id) == 'done'
    assert queue.finish(consumer, job_id) is False


def test_retry_waits_before_the_next_claim(pgsql, consumer):
    job_id = queue.insert_job(pgsql)
    queue.claim(consumer)

    retried = queue.finish(
        consumer, job_id, state='pending', retry_after=queue.LEASE,
    )

    assert retried is True
    assert queue.job_state(pgsql, job_id) == 'pending'
    assert queue.claim(consumer) is None
