import seed
import waiting
import wire


def event(run):
    return wire.import_completed_message(
        run.run_id, run.scope, run.tool, seed.SCAN_ID,
    )


async def send(broker, run):
    await broker.publish(event(run), run.run_id)


async def process(broker, db, run):
    await send(broker, run)
    return await waiting.until(lambda: db.algo_version(run.run_id))
