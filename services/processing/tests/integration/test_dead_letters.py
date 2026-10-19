import uuid

import flow
import seed
import settings
import wire

GARBAGE = b'\xff\xff\xff'
RUNNING = 'running'
NO_TENANT = ('', 'payments', 'prod')


async def dead_message(broker):
    queue = await broker.queue(broker.topology.dead_queue)
    return await broker.get(queue)


async def test_unknown_run_is_dead_lettered(broker, db):
    body = wire.import_completed_message(
        str(uuid.uuid4()), settings.SCOPE, seed.TRIVY, seed.SCAN_ID,
    )

    await broker.publish(body, 'unknown-run')

    assert (await dead_message(broker)).body == body
    assert db.processed_runs() == 0


async def test_unfinished_run_is_dead_lettered(broker, db, seeder):
    run = seeder.run(settings.SCOPE, seed.TRIVY, status=RUNNING)

    await flow.send(broker, run)

    assert (await dead_message(broker)).body == flow.event(run)
    assert db.processed_runs() == 0


async def test_undecodable_message_is_dead_lettered(broker):
    await broker.publish(GARBAGE, 'garbage')

    assert (await dead_message(broker)).body == GARBAGE


async def test_message_without_tenant_is_dead_lettered(broker):
    body = wire.import_completed_message(
        str(uuid.uuid4()), NO_TENANT, seed.TRIVY, seed.SCAN_ID,
    )

    await broker.publish(body, 'no-tenant')

    assert (await dead_message(broker)).body == body
