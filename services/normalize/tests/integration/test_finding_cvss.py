import psycopg2
import pytest

from finding_sql import INSERT_CVSS, INSERT_FINDING

MISSING_FINDING = '00000000-0000-0000-0000-000000000000'
VERSION = '3.1'
SCORE = 9.8
INVALID = (('4.0', SCORE), (VERSION, 10.1), (VERSION, -0.1))


@pytest.fixture
def finding_id(cursor, run_id):
    cursor.execute(INSERT_FINDING, (run_id,))
    cursor.execute('SELECT id FROM finding')
    return cursor.fetchone()[0]


def test_finding_keeps_a_score_per_source(cursor, finding_id):
    cursor.execute(INSERT_CVSS, (finding_id, VERSION, SCORE))

    cursor.execute('SELECT source, version, score FROM finding_cvss')

    assert cursor.fetchone() == ('nvd', VERSION, SCORE)


def test_same_source_and_vector_is_stored_once(cursor, finding_id):
    cursor.execute(INSERT_CVSS, (finding_id, VERSION, SCORE))

    with pytest.raises(psycopg2.errors.UniqueViolation):
        cursor.execute(INSERT_CVSS, (finding_id, VERSION, SCORE))


def test_score_needs_an_existing_finding(cursor):
    with pytest.raises(psycopg2.errors.ForeignKeyViolation):
        cursor.execute(INSERT_CVSS, (MISSING_FINDING, VERSION, SCORE))


@pytest.mark.parametrize('invalid', INVALID)
def test_version_and_score_are_validated(cursor, finding_id, invalid):
    with pytest.raises(psycopg2.errors.CheckViolation):
        cursor.execute(INSERT_CVSS, (finding_id, *invalid))
