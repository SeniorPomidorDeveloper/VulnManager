import flow
import settings

LEVELS_TRIVY = (('l0', settings.FINDINGS), ('l1', settings.FINDINGS))
LEVELS_SEMGREP = (('l0', settings.FINDINGS), ('l2', settings.FINDINGS))
LEVELS_FALLBACK = (('l0', settings.FINDINGS),)
CUSTOM_TOOL = 'custom-scanner'


async def test_trivy_run_gets_identity_fingerprints(broker, db, seeder):
    run = seeder.trivy_run(settings.SCOPE)

    algo = await flow.process(broker, db, run)

    assert algo == settings.TRIVY_ALGO
    assert db.levels(run.run_id) == LEVELS_TRIVY


async def test_semgrep_run_gets_structural_fingerprints(broker, db, seeder):
    run = seeder.semgrep_run(settings.SCOPE)

    algo = await flow.process(broker, db, run)

    assert algo == settings.SEMGREP_ALGO
    assert db.levels(run.run_id) == LEVELS_SEMGREP


async def test_unknown_tool_gets_fallback_fingerprint(broker, db, seeder):
    run = seeder.unknown_tool_run(settings.SCOPE, CUSTOM_TOOL)

    algo = await flow.process(broker, db, run)

    assert algo == settings.FALLBACK_ALGO
    assert db.levels(run.run_id) == LEVELS_FALLBACK
