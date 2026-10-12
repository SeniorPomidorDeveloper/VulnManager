import psycopg2
import pytest

import queue_client as queue
import settings


def test_empty_queue_returns_nothing(consumer):
    assert queue.claim(consumer) is None


def test_claim_returns_the_job_and_leases_it(pgsql, consumer):
    job_id = queue.insert_job(pgsql)

    first = queue.claim(consumer)

    assert first == (job_id, settings.TENANT, 'payments', 'prod', 'trivy', 1)
    assert queue.claim(consumer) is None
    assert queue.job_state(pgsql, job_id) == 'running'


def test_expired_lease_is_claimed_again(pgsql, consumer):
    job_id = queue.insert_job(pgsql)
    queue.claim(consumer, lease=queue.EXPIRED)

    again = queue.claim(consumer, worker=queue.OTHER_WORKER)

    assert again[0] == job_id
    assert again[-1] == 2


def test_claim_crosses_tenants(pgsql, consumer):
    queue.insert_job(pgsql)
    queue.insert_job(pgsql, tenant=queue.OTHER_TENANT)

    first = queue.claim(consumer)
    second = queue.claim(consumer)

    assert {first[1], second[1]} == {settings.TENANT, queue.OTHER_TENANT}


def test_consumer_cannot_touch_the_table(pgsql, consumer):
    queue.insert_job(pgsql)

    with pytest.raises(psycopg2.errors.InsufficientPrivilege):
        consumer.execute('SELECT * FROM ingest_job')
