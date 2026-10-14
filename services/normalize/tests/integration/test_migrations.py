import psycopg2
import pytest

from finding_sql import (
    INSERT_FINDING,
    INSERT_FINDING_SEVERITY,
    INSERT_RUN,
    MISSING_RUN,
)
from settings import DATABASE


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


def test_finding_severity_defaults_to_unknown(pgsql):
    cursor = pgsql[DATABASE].cursor()
    cursor.execute(INSERT_RUN, ('completed',))
    run_id = cursor.fetchone()[0]
    cursor.execute(INSERT_FINDING, (run_id,))

    cursor.execute('SELECT severity FROM finding')

    assert cursor.fetchone()[0] == 'unknown'


def test_unknown_severity_value_is_rejected(pgsql):
    cursor = pgsql[DATABASE].cursor()
    cursor.execute(INSERT_RUN, ('completed',))
    run_id = cursor.fetchone()[0]

    with pytest.raises(psycopg2.errors.CheckViolation):
        cursor.execute(INSERT_FINDING_SEVERITY, (run_id, 'extreme'))
