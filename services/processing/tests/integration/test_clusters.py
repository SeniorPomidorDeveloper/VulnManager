import functools

import flow
import metrics
import settings
import waiting


async def test_repeated_report_joins_clusters(broker, db, seeder):
    first = seeder.trivy_run(settings.SCOPE)
    second = seeder.trivy_run(settings.SCOPE)

    await flow.process(broker, db, first)
    await flow.process(broker, db, second)

    assert db.members(second.run_id) == settings.FINDINGS
    assert db.joined(second.run_id, first.run_id) == settings.FINDINGS
    assert db.clusters() == settings.FINDINGS


async def test_same_findings_in_other_scope_stay_apart(broker, db, seeder):
    first = seeder.semgrep_run(settings.SCOPE)
    second = seeder.semgrep_run(settings.OTHER_SCOPE)

    await flow.process(broker, db, first)
    await flow.process(broker, db, second)

    assert db.joined(second.run_id, first.run_id) == 0
    assert db.clusters() == 2 * settings.FINDINGS


async def test_redelivered_event_is_processed_once(
    broker, db, seeder, service_client,
):
    run = seeder.trivy_run(settings.SCOPE)
    acked = await metrics.acked_messages(service_client)

    await flow.send(broker, run)
    await waiting.until(
        functools.partial(metrics.acked_equals, service_client, acked + 1),
    )
    await flow.send(broker, run)
    await waiting.until(
        functools.partial(metrics.acked_equals, service_client, acked + 2),
    )

    assert db.processed_runs() == 1
    assert db.clusters() == settings.FINDINGS
