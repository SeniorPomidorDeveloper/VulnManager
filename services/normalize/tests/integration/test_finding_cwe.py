import psycopg2
import pytest

from finding_sql import INSERT_CWE, INSERT_FINDING, INSERT_FINDING_RULE

MISSING_FINDING = '00000000-0000-0000-0000-000000000000'
CWE = 'CWE-79'


@pytest.fixture
def finding_id(cursor, run_id):
    cursor.execute(INSERT_FINDING, (run_id,))
    cursor.execute('SELECT id FROM finding')
    return cursor.fetchone()[0]


def test_finding_keeps_several_cwe(cursor, finding_id):
    cursor.execute(INSERT_CWE, (finding_id, CWE))
    cursor.execute(INSERT_CWE, (finding_id, 'CWE-22'))

    cursor.execute('SELECT cwe FROM finding_cwe ORDER BY cwe')

    assert cursor.fetchall() == [('CWE-22',), (CWE,)]


def test_same_cwe_is_stored_once_per_finding(cursor, finding_id):
    cursor.execute(INSERT_CWE, (finding_id, CWE))

    with pytest.raises(psycopg2.errors.UniqueViolation):
        cursor.execute(INSERT_CWE, (finding_id, CWE))


def test_cwe_needs_an_existing_finding(cursor):
    with pytest.raises(psycopg2.errors.ForeignKeyViolation):
        cursor.execute(INSERT_CWE, (MISSING_FINDING, CWE))


@pytest.mark.parametrize('bad', ['79', 'cwe-79', 'CWE-0', 'CWE-079', 'CWE-'])
def test_cwe_must_be_canonical(cursor, finding_id, bad):
    with pytest.raises(psycopg2.errors.CheckViolation):
        cursor.execute(INSERT_CWE, (finding_id, bad))


def test_rule_id_is_optional_and_stored(cursor, run_id):
    cursor.execute(INSERT_FINDING, (run_id,))
    cursor.execute(INSERT_FINDING_RULE, (run_id, 'rules.js-math-random'))

    cursor.execute('SELECT rule_id FROM finding ORDER BY rule_id NULLS LAST')

    assert cursor.fetchall() == [('rules.js-math-random',), (None,)]
