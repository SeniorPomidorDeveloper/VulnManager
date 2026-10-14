import psycopg2
import pytest

from finding_sql import INSERT_FINDING, INSERT_RATING

MISSING_FINDING = '00000000-0000-0000-0000-000000000000'
VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
CVSS = ('nvd', 'cvss', '3.1', VECTOR, 9.8)
SCANNER = ('semgrep', 'scanner', '', '', 8.5)


@pytest.fixture
def finding_id(cursor, run_id):
    cursor.execute(INSERT_FINDING, (run_id,))
    cursor.execute('SELECT id FROM finding')
    return cursor.fetchone()[0]


def test_one_table_keeps_cvss_and_scanner_scores(cursor, finding_id):
    cursor.execute(INSERT_RATING, (finding_id, *CVSS))
    cursor.execute(INSERT_RATING, (finding_id, *SCANNER))

    cursor.execute(
        'SELECT source, scheme, version, vector, score FROM finding_rating '
        'ORDER BY scheme',
    )

    assert cursor.fetchall() == [CVSS, SCANNER]


def test_same_rating_is_stored_once(cursor, finding_id):
    cursor.execute(INSERT_RATING, (finding_id, *SCANNER))

    with pytest.raises(psycopg2.errors.UniqueViolation):
        cursor.execute(INSERT_RATING, (finding_id, *SCANNER))


def test_rating_needs_an_existing_finding(cursor):
    with pytest.raises(psycopg2.errors.ForeignKeyViolation):
        cursor.execute(INSERT_RATING, (MISSING_FINDING, *SCANNER))


def test_score_cannot_be_negative(cursor, finding_id):
    with pytest.raises(psycopg2.errors.CheckViolation):
        cursor.execute(INSERT_RATING, (finding_id, 'x', 'epss', '', '', -0.1))
