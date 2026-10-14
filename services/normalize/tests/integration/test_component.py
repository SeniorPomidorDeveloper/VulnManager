import psycopg2
import pytest

from finding_sql import (
    INSERT_COMPONENT,
    INSERT_FINDING,
    INSERT_FINDING_COMPONENT,
    MISSING_RUN,
    UPSERT_COMPONENT,
)

TENANT = 'acme'


def test_component_is_unique_per_tenant(cursor):
    cursor.execute(INSERT_COMPONENT, (TENANT,))

    with pytest.raises(psycopg2.errors.UniqueViolation):
        cursor.execute(INSERT_COMPONENT, (TENANT,))


def test_component_is_per_tenant(cursor):
    cursor.execute(INSERT_COMPONENT, (TENANT,))
    cursor.execute(INSERT_COMPONENT, ('globex',))

    cursor.execute('SELECT count(*) FROM component')

    assert cursor.fetchone()[0] == 2


def test_upsert_returns_the_same_component(cursor):
    cursor.execute(UPSERT_COMPONENT, (TENANT,))
    first = cursor.fetchone()[0]

    cursor.execute(UPSERT_COMPONENT, (TENANT,))

    assert cursor.fetchone()[0] == first


def test_finding_references_an_existing_component(cursor, run_id):
    cursor.execute(INSERT_COMPONENT, (TENANT,))
    component_id = cursor.fetchone()[0]
    cursor.execute(INSERT_FINDING_COMPONENT, (run_id, component_id))

    cursor.execute('SELECT component_id FROM finding')

    assert cursor.fetchone()[0] == component_id


def test_finding_rejects_a_missing_component(cursor, run_id):
    with pytest.raises(psycopg2.errors.ForeignKeyViolation):
        cursor.execute(INSERT_FINDING_COMPONENT, (run_id, MISSING_RUN))


def test_finding_without_component_stores_null(cursor, run_id):
    cursor.execute(INSERT_FINDING, (run_id,))

    cursor.execute('SELECT component_id FROM finding')

    assert cursor.fetchone()[0] is None
