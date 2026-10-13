import psycopg2
import pytest

from settings import DATABASE

MISSING_RUN = '00000000-0000-0000-0000-000000000000'
INSERT_RUN = (
    'INSERT INTO import_run (tenant_id, scope_key, product_id, context_id, '
    'tool_name, scan_id, raw_key, raw_sha256, status) '
    "VALUES ('acme', 'scope', 'p', 'c', 'trivy', 's', 'key', 'sha', %s) "
    'RETURNING id'
)
INSERT_FINDING = (
    'INSERT INTO finding (tenant_id, import_run_id, scope_key, product_id, '
    'context_id, tool_finding_id, kind, title, description, severity_raw, '
    'raw, provenance, algo_version, detected_at) '
    "VALUES ('acme', %s, 'scope', 'p', 'c', 'id', 'sca', 't', 'd', 'HIGH', "
    "'{}', '{}', 'trivy@1', now())"
)


def test_report_key_is_unique(pgsql):
    cursor = pgsql[DATABASE].cursor()
    cursor.execute(INSERT_RUN, ('running',))

    with pytest.raises(psycopg2.errors.UniqueViolation):
        cursor.execute(INSERT_RUN, ('running',))


def test_unknown_status_is_rejected(pgsql):
    cursor = pgsql[DATABASE].cursor()

    with pytest.raises(psycopg2.errors.CheckViolation):
        cursor.execute(INSERT_RUN, ('stuck',))


def test_finding_requires_an_import_run(pgsql):
    cursor = pgsql[DATABASE].cursor()

    with pytest.raises(psycopg2.errors.ForeignKeyViolation):
        cursor.execute(INSERT_FINDING, (MISSING_RUN,))


def test_finding_is_stored_for_an_existing_run(pgsql):
    cursor = pgsql[DATABASE].cursor()
    cursor.execute(INSERT_RUN, ('completed',))
    run_id = cursor.fetchone()[0]

    cursor.execute(INSERT_FINDING, (run_id,))

    cursor.execute(
        'SELECT count(*) FROM finding WHERE import_run_id = %s', (run_id,),
    )
    assert cursor.fetchone()[0] == 1
